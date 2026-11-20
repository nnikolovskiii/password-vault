package com.nnikolovskii.vault

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import com.nnikolovskii.vault.crypto.Argon2Kdf
import com.nnikolovskii.vault.crypto.KdfCalibrator
import com.nnikolovskii.vault.crypto.KeyHierarchy
import com.nnikolovskii.vault.crypto.KeystoreBiometricKey
import com.nnikolovskii.vault.crypto.KeystoreDeviceWrap
import com.nnikolovskii.vault.data.VaultDatabase
import com.nnikolovskii.vault.data.VaultRepository
import com.nnikolovskii.vault.session.AutoLock
import com.nnikolovskii.vault.session.ClipboardGuard
import com.nnikolovskii.vault.session.PrefsBackoffStore
import com.nnikolovskii.vault.session.VaultSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class VaultApp : Application() {
    lateinit var session: VaultSession
        private set
    lateinit var repository: VaultRepository
        private set
    lateinit var clipboard: ClipboardGuard
        private set
    lateinit var autoLock: AutoLock
        private set

    /** Floor-params Argon2id time from the last create (debug timing line only). */
    @Volatile
    var lastFloorMillis: Long? = null
        private set

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    override fun onCreate() {
        super.onCreate()
        val database = VaultDatabase.create(this)
        val deviceWrap = KeystoreDeviceWrap(this)
        val calibrator = KdfCalibrator(Argon2Kdf, SystemClock::elapsedRealtime)
        val hierarchy = KeyHierarchy(
            kdf = Argon2Kdf,
            deviceWrap = deviceWrap,
            chooseIterations = { salt ->
                val c = calibrator.calibrate(salt)
                lastFloorMillis = c.floorMillis
                c.iterations
            },
            clock = SystemClock::elapsedRealtime,
        )
        session = VaultSession()
        repository = VaultRepository(
            metaDao = database.meta(),
            entryDao = database.entries(),
            hierarchy = hierarchy,
            deviceWrap = deviceWrap,
            biometricKey = KeystoreBiometricKey(this),
            session = session,
            backoffStore = PrefsBackoffStore(this),
            transactor = database.transactor,
        )
        val settings = repository.settings
        clipboard = ClipboardGuard(
            this,
            isForeground = {
                ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
            },
            clearAfterMillis = { settings.value.clipboardClearMillis },
        )
        autoLock = AutoLock(this, session, clipboard) { settings.value }.also { it.install() }
        appScope.launch { repository.refreshRestingState() }
        appScope.launch { settings.collect { autoLock.onSettingsChanged() } }
    }
}
