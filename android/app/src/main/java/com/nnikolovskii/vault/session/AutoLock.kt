package com.nnikolovskii.vault.session

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.nnikolovskii.vault.domain.AutoLockPolicy
import com.nnikolovskii.vault.domain.VaultSettings

/**
 * Drives [AutoLockPolicy] from the platform: screen off (receiver registered only while
 * unlocked), process ON_STOP / ON_START, user interaction, and a timer. Times are
 * SystemClock.elapsedRealtime. Main thread only. The background and idle timeouts come from the
 * vault's settings (Part 3), read at unlock and again whenever they change.
 */
class AutoLock(
    private val context: Context,
    private val session: VaultSession,
    private val clipboard: ClipboardGuard,
    private val settings: () -> VaultSettings,
) : DefaultLifecycleObserver, VaultSession.Listener {

    private val policy = AutoLockPolicy()
    private val handler = Handler(Looper.getMainLooper())
    private val tick = Runnable { evaluate() }
    private var receiverRegistered = false

    private val screenOff = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_SCREEN_OFF) lockNow(policy.onScreenOff())
        }
    }

    fun install() {
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
        session.addListener(this)
    }

    private fun now() = SystemClock.elapsedRealtime()

    private fun inForeground() =
        ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)

    /** Activity.onUserInteraction. */
    fun onUserInteraction() {
        policy.onInteraction(now())
    }

    /**
     * ON_START, called from the activity's onStart as well as the process observer, so the
     * check runs before the first frame. Idempotent.
     */
    fun onAppStart() {
        if (!session.isUnlocked) return
        val reason = policy.onForeground(now())
        if (reason != null) lockNow(reason) else schedule()
    }

    override fun onStart(owner: LifecycleOwner) = onAppStart()

    override fun onStop(owner: LifecycleOwner) {
        if (!session.isUnlocked) return
        policy.onBackground(now())
        schedule()
    }

    /** Settings changed (or were decrypted at unlock): new timeouts apply to the running countdowns. */
    fun onSettingsChanged() {
        handler.post {
            applyTimeouts()
            if (session.isUnlocked) evaluate()
        }
    }

    private fun applyTimeouts() {
        val s = settings()
        policy.setTimeouts(s.backgroundLockMillis, s.idleLockMillis)
    }

    override fun onUnlocked() {
        handler.post {
            if (!session.isUnlocked) return@post
            applyTimeouts()
            policy.onUnlocked(now(), inForeground())
            registerScreenOff()
            SessionService.start(context)
            schedule()
        }
    }

    override fun onLocked() {
        handler.post {
            handler.removeCallbacks(tick)
            unregisterScreenOff()
            SessionService.stop(context)
            clipboard.onLock()
        }
    }

    private fun evaluate() {
        if (!session.isUnlocked) return
        val reason = policy.check(now())
        if (reason != null) lockNow(reason) else schedule()
    }

    private fun schedule() {
        handler.removeCallbacks(tick)
        if (!session.isUnlocked) return
        val delay = (policy.nextDeadline() - now()).coerceAtLeast(0) + TICK_SLACK_MILLIS
        handler.postDelayed(tick, delay)
    }

    @Suppress("UNUSED_PARAMETER")
    private fun lockNow(reason: AutoLockPolicy.Reason) {
        session.lock()
    }

    private fun registerScreenOff() {
        if (receiverRegistered) return
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(screenOff, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(screenOff, filter)
        }
        receiverRegistered = true
    }

    private fun unregisterScreenOff() {
        if (!receiverRegistered) return
        try {
            context.unregisterReceiver(screenOff)
        } catch (_: IllegalArgumentException) {
        }
        receiverRegistered = false
    }

    private companion object {
        const val TICK_SLACK_MILLIS = 250L
    }
}
