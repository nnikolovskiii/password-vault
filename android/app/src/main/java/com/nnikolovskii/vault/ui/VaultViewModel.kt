package com.nnikolovskii.vault.ui

import android.app.KeyguardManager
import android.net.Uri
import android.provider.DocumentsContract
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nnikolovskii.vault.BuildConfig
import com.nnikolovskii.vault.VaultApp
import com.nnikolovskii.vault.crypto.BackupCodec
import com.nnikolovskii.vault.crypto.BackupFile
import com.nnikolovskii.vault.crypto.BackupFormatException
import com.nnikolovskii.vault.data.BackupPreview
import com.nnikolovskii.vault.data.BiometricEnableStart
import com.nnikolovskii.vault.data.BiometricStart
import com.nnikolovskii.vault.data.BiometricStatus
import com.nnikolovskii.vault.data.ChangeOutcome
import com.nnikolovskii.vault.data.DamagedEntryException
import com.nnikolovskii.vault.data.ExportOutcome
import com.nnikolovskii.vault.data.ReauthFailure
import com.nnikolovskii.vault.data.RestoreOutcome
import com.nnikolovskii.vault.data.UnlockOutcome
import com.nnikolovskii.vault.domain.BackupReminder
import com.nnikolovskii.vault.domain.CodecException
import com.nnikolovskii.vault.domain.EntryDraft
import com.nnikolovskii.vault.domain.EntryRow
import com.nnikolovskii.vault.domain.EntrySecret
import com.nnikolovskii.vault.domain.GeneratorOptions
import com.nnikolovskii.vault.domain.PassphraseRules
import com.nnikolovskii.vault.domain.PasswordGenerator
import com.nnikolovskii.vault.domain.Search
import com.nnikolovskii.vault.domain.Tags
import com.nnikolovskii.vault.domain.VaultSettings
import com.nnikolovskii.vault.session.SessionState
import com.nnikolovskii.vault.session.VaultLockedException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.time.Instant
import java.time.ZoneId
import kotlin.math.roundToInt

/** Where the Unlocked part of the app is. Create / Unlock / Device key lost follow the session. */
sealed interface Screen {
    data object List : Screen
    data class Detail(val id: String) : Screen
    data class Edit(val id: String?) : Screen
    data object Export : Screen
    data object ChangePassphrase : Screen
    data object Settings : Screen
}

/** Settings screen: the biometric switch's passphrase step. */
class SettingsUi(
    /** The passphrase form for turning biometric unlock on is open. */
    val enabling: Boolean = false,
    val busy: Boolean = false,
    val message: String? = null,
    val isError: Boolean = false,
)

/** Generator dialog over Add / Edit. [preview] is a String because Compose needs one. */
class GeneratorUi(val options: GeneratorOptions, val preview: String, val bits: Int) {
    override fun toString(): String = "GeneratorUi(${options.mode}, redacted)"
}

/** Export / change passphrase form state. */
class PassphraseTaskUi(
    val busy: Boolean = false,
    val message: String? = null,
    /** Export only: the file is built and waits for a destination (picker cancelled). */
    val readyEntries: Int? = null,
)

/** Restore flow (Create / Device key lost): a picked, parsed file waiting for its passphrase. */
class RestoreUi(
    val preview: BackupPreview,
    val busy: Boolean = false,
    val message: String? = null,
)

/** SAF pickers live at the root (always composed), so a lock mid-pick does not drop the result. */
sealed interface PickerRequest {
    class SaveBackup(val fileName: String) : PickerRequest
    data object OpenBackup : PickerRequest
}

/** List header: "Last backup: …", plus the reminder card when [remind]. */
class BackupBanner(val label: String, val remind: Boolean)

class UnlockUi(
    val busy: Boolean = false,
    val message: String? = null,
    val backoffRemainingMillis: Long = 0L,
    /** Debug builds only: the KDF timing line for the on-device gate. */
    val debugTiming: String? = null,
)

class CreateUi(
    val busy: Boolean = false,
    val error: String? = null,
    val deviceSecure: Boolean = true,
)

/** Revealed values are Strings because Compose Text needs them; dropped on hide / leave / lock. */
class DetailUi(
    val row: EntryRow? = null,
    val password: String? = null,
    val notes: String? = null,
) {
    override fun toString(): String = "DetailUi(redacted)"
}

/** Add / Edit form. In the ViewModel (survives rotation), never in saved state. */
class EditForm(
    val id: String?,
    val title: String = "",
    val username: String = "",
    val url: String = "",
    val password: String = "",
    val notes: String = "",
    /** Comma-separated, as typed. Parsed by [Tags.parse] on save. */
    val tags: String = "",
    val saving: Boolean = false,
    val error: String? = null,
    private val original: EditForm? = null,
) {
    val canSave: Boolean get() = title.isNotBlank() && !saving

    val dirty: Boolean
        get() {
            val o = original ?: return title.isNotEmpty() || username.isNotEmpty() ||
                url.isNotEmpty() || password.isNotEmpty() || notes.isNotEmpty() || tags.isNotBlank()
            return title != o.title || username != o.username || url != o.url ||
                password != o.password || notes != o.notes || Tags.parse(tags) != Tags.parse(o.tags)
        }

    fun with(
        title: String = this.title,
        username: String = this.username,
        url: String = this.url,
        password: String = this.password,
        notes: String = this.notes,
        tags: String = this.tags,
        saving: Boolean = this.saving,
        error: String? = this.error,
    ) = EditForm(id, title, username, url, password, notes, tags, saving, error, original)

    fun asOriginal() = EditForm(id, title, username, url, password, notes, tags, original = this)

    override fun toString(): String = "EditForm(id=$id, redacted)"
}

class VaultViewModel(private val app: VaultApp) : ViewModel() {
    private val repository = app.repository
    private val clipboard = app.clipboard

    val session: StateFlow<SessionState> = app.session.state

    private val _screen = MutableStateFlow<Screen>(Screen.List)
    val screen: StateFlow<Screen> = _screen.asStateFlow()

    val rows: StateFlow<List<EntryRow>> = repository.observeRows()
        .flowOn(Dispatchers.Default)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    /** Search box and tag filter. In memory only, cleared on lock. */
    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()
    private val _tagFilter = MutableStateFlow<String?>(null)
    val tagFilter: StateFlow<String?> = _tagFilter.asStateFlow()

    val visibleRows: StateFlow<List<EntryRow>> = combine(rows, _query, _tagFilter) { r, q, t ->
        Search.filter(r, q, t)
    }
        .flowOn(Dispatchers.Default)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val tagsInUse: StateFlow<List<String>> = rows
        .map { r -> Tags.inUse(r.filterIsInstance<EntryRow.Ok>().map { it.summary }) }
        .flowOn(Dispatchers.Default)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val settings: StateFlow<VaultSettings> = repository.settings

    val biometricEnabled: StateFlow<Boolean> = repository.observeBiometricEnabled()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    /** Lock screen: offer biometric unlock? */
    private val _biometric = MutableStateFlow(BiometricStatus.Off)
    val biometric: StateFlow<BiometricStatus> = _biometric.asStateFlow()

    private val _biometricHardware = MutableStateFlow(BiometricSupport.Availability.Unsupported)
    val biometricHardware: StateFlow<BiometricSupport.Availability> = _biometricHardware.asStateFlow()

    private val _settingsUi = MutableStateFlow(SettingsUi())
    val settingsUi: StateFlow<SettingsUi> = _settingsUi.asStateFlow()

    private val _generator = MutableStateFlow<GeneratorUi?>(null)
    val generator: StateFlow<GeneratorUi?> = _generator.asStateFlow()
    private val passwordGenerator = PasswordGenerator()

    /** One prompt at a time; a newer request replaces one the UI has not shown yet. */
    private val biometricRequests = Channel<BiometricRequest>(Channel.CONFLATED)
    val biometricPrompts = biometricRequests.receiveAsFlow()

    /** Show the biometric prompt by itself once, after the app comes back while locked. */
    private var autoBiometric = false
    private var biometricBusy = false

    private val _unlock = MutableStateFlow(UnlockUi())
    val unlock: StateFlow<UnlockUi> = _unlock.asStateFlow()

    private val _create = MutableStateFlow(CreateUi())
    val create: StateFlow<CreateUi> = _create.asStateFlow()

    private val _detail = MutableStateFlow(DetailUi())
    val detail: StateFlow<DetailUi> = _detail.asStateFlow()

    private val _edit = MutableStateFlow<EditForm?>(null)
    val edit: StateFlow<EditForm?> = _edit.asStateFlow()

    private val messages = Channel<String>(Channel.BUFFERED)
    val snackbar = messages.receiveAsFlow()

    private val pickerRequests = Channel<PickerRequest>(Channel.BUFFERED)
    val pickers = pickerRequests.receiveAsFlow()

    val backup: StateFlow<BackupBanner?> = combine(repository.observeBackupInfo(), rows) { info, rows ->
        info?.let {
            val status = BackupReminder.status(it, rows.size, System.currentTimeMillis())
            BackupBanner(BackupReminder.label(status), status.remind)
        }
    }
        .flowOn(Dispatchers.Default)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    private val _export = MutableStateFlow(PassphraseTaskUi())
    val export: StateFlow<PassphraseTaskUi> = _export.asStateFlow()

    private val _change = MutableStateFlow(PassphraseTaskUi())
    val change: StateFlow<PassphraseTaskUi> = _change.asStateFlow()

    private val _restore = MutableStateFlow<RestoreUi?>(null)
    val restore: StateFlow<RestoreUi?> = _restore.asStateFlow()

    /** Detail's decrypted secret, wiped on hide / leave / lock. */
    private var revealed: EntrySecret? = null
    private var backoffJob: Job? = null

    /** Built `.pvault` bytes (ciphertext) waiting for a SAF destination. */
    private var pendingExport: ExportOutcome.Ready? = null
    private var savePickerOpen = false

    /** A file written after the vault locked: recorded as the last backup on the next unlock. */
    private var pendingBackupMark: Long? = null

    /** Parsed file for the restore flow (ciphertext). */
    private var restoreFile: BackupFile? = null

    init {
        viewModelScope.launch {
            session.collect { state ->
                if (state != SessionState.Unlocked && state != SessionState.Unlocking) dropPlaintext()
                if (state == SessionState.Locked) {
                    startBackoffTicker()
                    refreshBiometric()
                }
                if (state == SessionState.Unlocked) {
                    autoBiometric = false
                    clearRestore()
                    applyPendingBackupMark()
                }
            }
        }
    }

    // --- Create ------------------------------------------------------------------------------

    fun refreshDeviceSecure() {
        val keyguard = app.getSystemService(KeyguardManager::class.java)
        _create.update { CreateUi(it.busy, it.error, keyguard.isDeviceSecure) }
    }

    fun createVault(passphrase: String, confirm: String, acknowledged: Boolean) {
        if (_create.value.busy) return
        refreshDeviceSecure()
        if (!_create.value.deviceSecure) return
        if (!PassphraseRules.check(passphrase, confirm, acknowledged).ok) return
        _create.value = CreateUi(busy = true)
        viewModelScope.launch {
            try {
                repository.createVault(PassphraseRules.encode(passphrase))
                _create.value = CreateUi()
                _screen.value = Screen.List
            } catch (e: Exception) {
                _create.value = CreateUi(error = "Could not create the vault. Try again.")
            }
        }
    }

    // --- Unlock ------------------------------------------------------------------------------

    fun unlock(passphrase: String) {
        val ui = _unlock.value
        if (ui.busy || ui.backoffRemainingMillis > 0 || passphrase.isEmpty()) return
        _unlock.value = UnlockUi(busy = true, debugTiming = ui.debugTiming)
        viewModelScope.launch {
            val outcome = try {
                repository.unlock(PassphraseRules.encode(passphrase))
            } catch (e: Exception) {
                _unlock.value = UnlockUi(message = "Could not unlock. Try again.")
                return@launch
            }
            when (outcome) {
                is UnlockOutcome.Unlocked -> {
                    _unlock.value = UnlockUi(debugTiming = timing(outcome.kdfMillis))
                    _screen.value = Screen.List
                }
                is UnlockOutcome.WrongPassphrase -> {
                    _unlock.value = UnlockUi(
                        message = "Wrong passphrase",
                        debugTiming = timing(outcome.kdfMillis),
                    )
                    startBackoffTicker()
                }
                is UnlockOutcome.BackoffActive -> startBackoffTicker()
                UnlockOutcome.DeviceLocked ->
                    _unlock.value = UnlockUi(message = "Unlock the phone first, then try again.")
                UnlockOutcome.DeviceKeyLost, UnlockOutcome.Interrupted,
                UnlockOutcome.PassphraseRequired, UnlockOutcome.BiometricInvalidated,
                -> _unlock.value = UnlockUi()
            }
        }
    }

    // --- Biometric unlock --------------------------------------------------------------------

    /** MainActivity.onStart, after the auto-lock check: arm the automatic prompt if locked. */
    fun onForeground() {
        // A prompt that was showing when the app left has been cancelled by now.
        biometricBusy = false
        val state = session.value
        autoBiometric = state != SessionState.Unlocked && state != SessionState.Unlocking
        if (state == SessionState.Locked) refreshBiometric()
    }

    private fun refreshBiometric() {
        viewModelScope.launch {
            val status = try {
                repository.biometricStatus()
            } catch (e: Exception) {
                BiometricStatus.Off
            }
            if (status == BiometricStatus.Invalidated) {
                _biometric.value = BiometricStatus.Off
                _unlock.update { UnlockUi(it.busy, BIOMETRIC_INVALIDATED, it.backoffRemainingMillis, it.debugTiming) }
                return@launch
            }
            _biometric.value = status
            if (status == BiometricStatus.Ready && autoBiometric && session.value == SessionState.Locked) {
                autoBiometric = false
                unlockWithBiometric()
            }
        }
    }

    fun unlockWithBiometric() {
        if (biometricBusy || _unlock.value.busy) return
        biometricBusy = true
        viewModelScope.launch {
            val start = try {
                repository.beginBiometricUnlock()
            } catch (e: Exception) {
                BiometricStart.Off
            }
            when (start) {
                is BiometricStart.Ready -> {
                    biometricRequests.trySend(BiometricRequest.Unlock(start.cipher))
                    return@launch // Busy until the prompt answers.
                }
                BiometricStart.PassphraseDue -> _biometric.value = BiometricStatus.PassphraseDue
                BiometricStart.Invalidated -> {
                    _biometric.value = BiometricStatus.Off
                    _unlock.update { UnlockUi(it.busy, BIOMETRIC_INVALIDATED, it.backoffRemainingMillis, it.debugTiming) }
                }
                BiometricStart.Off -> _biometric.value = BiometricStatus.Off
            }
            biometricBusy = false
        }
    }

    /** The prompt's answer, from VaultRoot. */
    fun onBiometricResult(request: BiometricRequest, result: BiometricResult) {
        when (request) {
            is BiometricRequest.Unlock -> onBiometricUnlock(result)
            is BiometricRequest.Enable -> onBiometricEnable(result)
        }
    }

    private fun onBiometricUnlock(result: BiometricResult) {
        if (result !is BiometricResult.Succeeded) {
            biometricBusy = false
            if (result is BiometricResult.Error) {
                _unlock.update {
                    UnlockUi(it.busy, result.message ?: "Biometric unlock failed. Use your passphrase.", it.backoffRemainingMillis, it.debugTiming)
                }
            }
            return
        }
        viewModelScope.launch {
            val outcome = try {
                repository.finishBiometricUnlock(result.cipher)
            } catch (e: Exception) {
                UnlockOutcome.Interrupted
            } finally {
                biometricBusy = false
            }
            val ui = _unlock.value
            when (outcome) {
                is UnlockOutcome.Unlocked -> {
                    _unlock.value = UnlockUi(debugTiming = ui.debugTiming)
                    _screen.value = Screen.List
                }
                UnlockOutcome.PassphraseRequired -> _biometric.value = BiometricStatus.PassphraseDue
                UnlockOutcome.BiometricInvalidated -> {
                    _biometric.value = BiometricStatus.Off
                    _unlock.value = UnlockUi(message = BIOMETRIC_INVALIDATED, backoffRemainingMillis = ui.backoffRemainingMillis, debugTiming = ui.debugTiming)
                }
                UnlockOutcome.DeviceLocked ->
                    _unlock.value = UnlockUi(message = "Unlock the phone first, then try again.", backoffRemainingMillis = ui.backoffRemainingMillis, debugTiming = ui.debugTiming)
                else -> Unit
            }
        }
    }

    private fun timing(kdfMillis: Long): String? {
        if (!BuildConfig.DEBUG) return null
        val floor = app.lastFloorMillis?.let { " · floor t=3: $it ms" } ?: ""
        val gate = if (kdfMillis > 2_500) " · OVER 2.5 s GATE" else ""
        return "Argon2id 64 MiB: $kdfMillis ms$floor$gate"
    }

    private fun startBackoffTicker() {
        backoffJob?.cancel()
        backoffJob = viewModelScope.launch {
            while (true) {
                val remaining = repository.backoff().remainingMillis(System.currentTimeMillis())
                val ui = _unlock.value
                _unlock.value = UnlockUi(ui.busy, ui.message, remaining, ui.debugTiming)
                if (remaining <= 0) break
                delay(minOf(remaining, 1_000L))
            }
        }
    }

    // --- Session -----------------------------------------------------------------------------

    fun lock() = app.session.lock()

    private fun dropPlaintext() {
        hideSecrets()
        _edit.value = null
        _generator.value = null
        _query.value = ""
        _tagFilter.value = null
        _settingsUi.value = SettingsUi()
        _detail.value = DetailUi()
        _export.value = PassphraseTaskUi()
        _change.value = PassphraseTaskUi()
        // A picker still open keeps its bytes: the file is ciphertext and he asked for it.
        if (!savePickerOpen) pendingExport = null
        _screen.value = Screen.List
    }

    // --- List / Detail -----------------------------------------------------------------------

    fun open(id: String) {
        hideSecrets()
        _screen.value = Screen.Detail(id)
        _detail.value = DetailUi()
        viewModelScope.launch {
            val row = try {
                repository.readSummary(id)
            } catch (e: VaultLockedException) {
                return@launch
            }
            if (row == null) {
                _screen.value = Screen.List
            } else if (_screen.value == Screen.Detail(id)) {
                _detail.update { DetailUi(row, it.password, it.notes) }
            }
        }
    }

    fun back() {
        when (val s = _screen.value) {
            is Screen.Detail -> {
                hideSecrets()
                _detail.value = DetailUi()
                _screen.value = Screen.List
            }
            is Screen.Edit -> {
                _edit.value = null
                _screen.value = if (s.id != null) Screen.Detail(s.id) else Screen.List
                if (s.id != null) open(s.id)
            }
            Screen.Export -> {
                if (_export.value.busy) return
                pendingExport = null
                _export.value = PassphraseTaskUi()
                _screen.value = Screen.List
            }
            Screen.ChangePassphrase -> {
                if (_change.value.busy) return
                _change.value = PassphraseTaskUi()
                _screen.value = Screen.List
            }
            Screen.Settings -> {
                if (_settingsUi.value.busy) return
                _settingsUi.value = SettingsUi()
                _screen.value = Screen.List
            }
            Screen.List -> clearFilter()
        }
    }

    fun togglePassword() {
        val d = _detail.value
        if (d.password != null) {
            _detail.value = DetailUi(d.row, null, d.notes)
            if (d.notes == null) hideSecrets()
            return
        }
        withSecret { secret -> _detail.update { DetailUi(it.row, String(secret.password), it.notes) } }
    }

    fun toggleNotes() {
        val d = _detail.value
        if (d.notes != null) {
            _detail.value = DetailUi(d.row, d.password, null)
            if (d.password == null) hideSecrets()
            return
        }
        withSecret { secret -> _detail.update { DetailUi(it.row, it.password, String(secret.notes)) } }
    }

    /** Re-masks everything and wipes the decrypted secret. Called on leaving Detail and on lock. */
    fun hideSecrets() {
        revealed?.wipe()
        revealed = null
        _detail.update { DetailUi(it.row) }
    }

    private fun withSecret(block: (EntrySecret) -> Unit) {
        val id = (_screen.value as? Screen.Detail)?.id ?: return
        revealed?.let { return block(it) }
        viewModelScope.launch {
            val secret = readSecretOrReport(id) ?: return@launch
            if (_screen.value != Screen.Detail(id) || !app.session.isUnlocked) {
                secret.wipe()
                return@launch
            }
            revealed = secret
            block(secret)
        }
    }

    fun copyPassword(id: String) {
        viewModelScope.launch {
            val secret = readSecretOrReport(id) ?: return@launch
            try {
                if (secret.password.isEmpty()) {
                    messages.trySend("No password saved")
                } else {
                    clipboard.copy("Password", secret.password)
                    messages.trySend("Password copied · clears in ${clipboardDelay()}")
                }
            } finally {
                secret.wipe()
            }
        }
    }

    fun copyField(label: String, value: String) {
        if (value.isEmpty()) return
        val chars = value.toCharArray()
        try {
            clipboard.copy(label, chars)
        } finally {
            chars.fill('\u0000')
        }
        messages.trySend("$label copied · clears in ${clipboardDelay()}")
    }

    private fun clipboardDelay(): String = formatSeconds(settings.value.clipboardClearSeconds)

    // --- Search ------------------------------------------------------------------------------

    fun setQuery(query: String) {
        _query.value = query
    }

    /** Tapping the selected chip again clears it. */
    fun toggleTagFilter(tag: String) {
        _tagFilter.value = if (_tagFilter.value?.let { Tags.sameTag(it, tag) } == true) null else tag
    }

    fun clearFilter() {
        _query.value = ""
        _tagFilter.value = null
    }

    /** Detail's tag chip: back to the list, showing only entries with that tag. */
    fun filterByTag(tag: String) {
        hideSecrets()
        _detail.value = DetailUi()
        _query.value = ""
        _tagFilter.value = tag
        _screen.value = Screen.List
    }

    private suspend fun readSecretOrReport(id: String): EntrySecret? =
        try {
            repository.readSecret(id)
        } catch (e: DamagedEntryException) {
            messages.trySend("This entry is damaged and cannot be opened")
            null
        } catch (e: VaultLockedException) {
            null
        }

    fun delete(id: String) {
        viewModelScope.launch {
            hideSecrets()
            repository.deleteEntry(id)
            _detail.value = DetailUi()
            _screen.value = Screen.List
            messages.trySend("Entry deleted")
        }
    }

    // --- Add / Edit --------------------------------------------------------------------------

    fun startAdd() {
        _edit.value = EditForm(id = null).asOriginal()
        _screen.value = Screen.Edit(null)
    }

    fun startEdit(id: String) {
        val summary = (_detail.value.row as? EntryRow.Ok)?.summary ?: return
        viewModelScope.launch {
            val secret = readSecretOrReport(id) ?: return@launch
            try {
                hideSecrets()
                _edit.value = EditForm(
                    id = id,
                    title = summary.title,
                    username = summary.username,
                    url = summary.url,
                    password = String(secret.password),
                    notes = String(secret.notes),
                    tags = Tags.format(summary.tags),
                ).asOriginal()
                _screen.value = Screen.Edit(id)
            } finally {
                secret.wipe()
            }
        }
    }

    fun updateForm(transform: (EditForm) -> EditForm) {
        _edit.update { it?.let(transform)?.with(error = null) }
    }

    fun save() {
        val form = _edit.value ?: return
        if (!form.canSave) return
        _edit.value = form.with(saving = true)
        val draft = EntryDraft(
            title = form.title.trim(),
            username = form.username,
            url = form.url.trim(),
            password = form.password.toCharArray(),
            notes = form.notes.toCharArray(),
            tags = Tags.parse(form.tags),
        )
        viewModelScope.launch {
            try {
                val id = repository.upsertEntry(form.id, draft)
                _edit.value = null
                open(id)
                messages.trySend("Saved")
            } catch (e: CodecException) {
                _edit.update { it?.with(saving = false, error = e.message) }
            } catch (e: DamagedEntryException) {
                _edit.update { it?.with(saving = false, error = "This entry is damaged; delete it instead.") }
            } catch (e: VaultLockedException) {
                // Lock already reset everything.
            }
        }
    }

    /** Edit screen: a tag chip from elsewhere in the vault, appended to the field. */
    fun addTag(tag: String) {
        updateForm { f ->
            val current = Tags.parse(f.tags)
            if (current.any { Tags.sameTag(it, tag) }) f else f.with(tags = Tags.format(current + tag))
        }
    }

    // --- Generator ---------------------------------------------------------------------------

    fun openGenerator() {
        regenerate(settings.value.generator)
    }

    fun updateGenerator(transform: (GeneratorOptions) -> GeneratorOptions) {
        val current = _generator.value?.options ?: return
        regenerate(transform(current))
    }

    fun regenerate() {
        _generator.value?.let { regenerate(it.options) }
    }

    private var generatorJob: Job? = null

    private fun regenerate(options: GeneratorOptions) {
        val o = options.sanitized()
        val bits = PasswordGenerator.entropyBits(o).roundToInt()
        // Options show at once (the slider must not lag); the new value follows.
        _generator.value?.let { _generator.value = GeneratorUi(o, it.preview, bits) }
        generatorJob?.cancel()
        generatorJob = viewModelScope.launch {
            // The first Words run loads the wordlist; keep it off the main thread.
            val preview = withContext(Dispatchers.Default) {
                val chars = passwordGenerator.generate(o)
                try {
                    String(chars)
                } finally {
                    chars.fill('\u0000')
                }
            }
            if (_edit.value == null) return@launch // Locked or left meanwhile.
            _generator.value = GeneratorUi(o, preview, bits)
        }
    }

    /** Puts the preview in the password field and remembers the options (encrypted settings). */
    fun useGenerated() {
        val g = _generator.value ?: return
        _generator.value = null
        updateForm { it.with(password = g.preview) }
        if (g.options != settings.value.generator) {
            viewModelScope.launch {
                try {
                    repository.updateSettings(settings.value.copy(generator = g.options))
                } catch (e: VaultLockedException) {
                    // Nothing to remember for a locked vault.
                }
            }
        }
    }

    fun closeGenerator() {
        _generator.value = null
    }

    // --- Settings ----------------------------------------------------------------------------

    fun startSettings() {
        _settingsUi.value = SettingsUi()
        refreshBiometricHardware()
        _screen.value = Screen.Settings
    }

    fun refreshBiometricHardware() {
        _biometricHardware.value = BiometricSupport.availability(app)
    }

    fun setBackgroundLock(seconds: Int) = saveSettings { it.copy(backgroundLockSeconds = seconds) }

    fun setIdleLock(seconds: Int) = saveSettings { it.copy(idleLockSeconds = seconds) }

    fun setClipboardClear(seconds: Int) = saveSettings { it.copy(clipboardClearSeconds = seconds) }

    private fun saveSettings(transform: (VaultSettings) -> VaultSettings) {
        viewModelScope.launch {
            try {
                repository.updateSettings(transform(settings.value))
            } catch (e: VaultLockedException) {
                // Lock reset the screen.
            } catch (e: Exception) {
                messages.trySend("Could not save the setting")
            }
        }
    }

    fun startEnableBiometric() {
        refreshBiometricHardware()
        _settingsUi.value = SettingsUi(enabling = true)
    }

    fun cancelEnableBiometric() {
        if (_settingsUi.value.busy) return
        _settingsUi.value = SettingsUi()
    }

    /** Proves the passphrase, makes a fresh biometric key, then asks for the prompt. */
    fun enableBiometric(passphrase: String) {
        if (_settingsUi.value.busy || passphrase.isEmpty()) return
        _settingsUi.value = SettingsUi(enabling = true, busy = true)
        viewModelScope.launch {
            val start = try {
                repository.beginEnableBiometric(PassphraseRules.encode(passphrase))
            } catch (e: VaultLockedException) {
                return@launch
            } catch (e: Exception) {
                _settingsUi.value = SettingsUi(enabling = true, message = "Could not turn on biometric unlock. Try again.", isError = true)
                return@launch
            }
            when (start) {
                is BiometricEnableStart.Ready -> biometricRequests.trySend(BiometricRequest.Enable(start.cipher))
                BiometricEnableStart.Unavailable -> _settingsUi.value = SettingsUi(
                    message = "No strong biometric (fingerprint or face) is set up on this phone.",
                    isError = true,
                )
                is ReauthFailure -> _settingsUi.value = SettingsUi(enabling = true, message = reauthMessage(start), isError = true)
            }
        }
    }

    private fun onBiometricEnable(result: BiometricResult) {
        viewModelScope.launch {
            val on = result is BiometricResult.Succeeded && try {
                repository.finishEnableBiometric(result.cipher)
            } catch (e: VaultLockedException) {
                false
            }
            if (!on) {
                // The fresh key from step 1 goes too: nothing half-enabled stays behind.
                runCatching { repository.disableBiometric() }
            }
            if (!app.session.isUnlocked) return@launch
            _settingsUi.value = when {
                on -> SettingsUi(message = "Biometric unlock is on. Your passphrase is still needed every 7 days.")
                result is BiometricResult.Error -> SettingsUi(message = result.message ?: "Biometric unlock was not turned on.", isError = true)
                else -> SettingsUi(message = "Biometric unlock was not turned on.")
            }
        }
    }

    fun disableBiometric() {
        viewModelScope.launch {
            try {
                repository.disableBiometric()
                _settingsUi.value = SettingsUi(message = "Biometric unlock is off.")
            } catch (e: Exception) {
                messages.trySend("Could not turn off biometric unlock")
            }
        }
    }

    // --- Export ------------------------------------------------------------------------------

    fun startExport() {
        pendingExport = null
        _export.value = PassphraseTaskUi()
        _screen.value = Screen.Export
    }

    /** Proves the passphrase, builds the file, then asks for a destination. */
    fun export(passphrase: String) {
        if (_export.value.busy || passphrase.isEmpty()) return
        _export.value = PassphraseTaskUi(busy = true)
        viewModelScope.launch {
            val outcome = try {
                repository.exportBackup(PassphraseRules.encode(passphrase))
            } catch (e: VaultLockedException) {
                return@launch
            } catch (e: Exception) {
                _export.value = PassphraseTaskUi(message = "Could not create the backup. Try again.")
                return@launch
            }
            when (outcome) {
                is ExportOutcome.Ready -> {
                    pendingExport = outcome
                    chooseExportDestination()
                }
                is ReauthFailure -> _export.value = PassphraseTaskUi(message = reauthMessage(outcome))
            }
        }
    }

    fun chooseExportDestination() {
        val ready = pendingExport ?: return
        savePickerOpen = true
        _export.value = PassphraseTaskUi(busy = true)
        pickerRequests.trySend(PickerRequest.SaveBackup(backupFileName(ready.exportedAt)))
    }

    /** SAF CreateDocument result. Null: cancelled, keep the bytes for another try. */
    fun onBackupDestination(uri: Uri?) {
        savePickerOpen = false
        val ready = pendingExport ?: return
        if (uri == null) {
            if (app.session.isUnlocked && _screen.value == Screen.Export) {
                _export.value = PassphraseTaskUi(readyEntries = ready.entryCount)
            } else {
                pendingExport = null
            }
            return
        }
        pendingExport = null
        viewModelScope.launch {
            val written = withContext(Dispatchers.IO) {
                try {
                    val out = app.contentResolver.openOutputStream(uri, "w") ?: throw IOException("No stream")
                    out.use { it.write(ready.bytes) }
                    true
                } catch (e: Exception) {
                    // Do not leave an empty or partial .pvault behind.
                    runCatching { DocumentsContract.deleteDocument(app.contentResolver, uri) }
                    false
                }
            }
            if (!written) {
                if (_screen.value == Screen.Export) {
                    _export.value = PassphraseTaskUi(message = "Could not write the backup file. Try another location.")
                } else {
                    messages.trySend("Could not write the backup file")
                }
                return@launch
            }
            pendingBackupMark = ready.exportedAt
            applyPendingBackupMark()
            _export.value = PassphraseTaskUi()
            if (_screen.value == Screen.Export) _screen.value = Screen.List
            messages.trySend("Backup saved · ${entries(ready.entryCount)}")
        }
    }

    private suspend fun applyPendingBackupMark() {
        val at = pendingBackupMark ?: return
        if (!app.session.isUnlocked) return
        try {
            repository.markBackedUp(at)
            pendingBackupMark = null
        } catch (e: VaultLockedException) {
            // Next unlock.
        }
    }

    private fun backupFileName(exportedAt: Long): String {
        val day = Instant.ofEpochMilli(exportedAt).atZone(ZoneId.systemDefault()).toLocalDate()
        return "vault-$day.pvault"
    }

    // --- Change passphrase -------------------------------------------------------------------

    fun startChangePassphrase() {
        _change.value = PassphraseTaskUi()
        _screen.value = Screen.ChangePassphrase
    }

    fun changePassphrase(current: String, new: String, confirm: String, acknowledged: Boolean) {
        if (_change.value.busy || current.isEmpty()) return
        if (!PassphraseRules.check(new, confirm, acknowledged).ok) return
        _change.value = PassphraseTaskUi(busy = true)
        viewModelScope.launch {
            val outcome = try {
                repository.changePassphrase(PassphraseRules.encode(current), PassphraseRules.encode(new))
            } catch (e: VaultLockedException) {
                return@launch
            } catch (e: Exception) {
                _change.value = PassphraseTaskUi(message = "Could not change the passphrase. Nothing was changed.")
                return@launch
            }
            when (outcome) {
                ChangeOutcome.Changed -> {
                    _change.value = PassphraseTaskUi()
                    if (_screen.value == Screen.ChangePassphrase) _screen.value = Screen.List
                    messages.trySend("Passphrase changed. Older backups still need the old one: export a new backup.")
                }
                is ReauthFailure -> _change.value = PassphraseTaskUi(message = reauthMessage(outcome))
            }
        }
    }

    private fun reauthMessage(failure: ReauthFailure): String = when (failure) {
        is ReauthFailure.WrongPassphrase -> {
            val wait = failure.backoff.remainingMillis(System.currentTimeMillis())
            if (wait > 0) "Wrong passphrase. Too many attempts: try again in ${formatCountdown(wait)}."
            else "Wrong passphrase"
        }
        is ReauthFailure.BackoffActive ->
            "Too many attempts. Try again in ${formatCountdown(failure.remainingMillis)}."
        ReauthFailure.DeviceLocked -> "Unlock the phone first, then try again."
        ReauthFailure.DeviceKeyLost ->
            "This phone's vault key is gone. Lock the vault and restore from a backup."
    }

    // --- Restore -----------------------------------------------------------------------------

    /** Create screen and Device key lost: pick a `.pvault` file. */
    fun startRestore() {
        refreshDeviceSecure()
        if (!_create.value.deviceSecure) {
            messages.trySend("Set a screen lock on the phone first")
            return
        }
        pickerRequests.trySend(PickerRequest.OpenBackup)
    }

    /** SAF OpenDocument result. */
    fun onBackupPicked(uri: Uri?) {
        uri ?: return
        viewModelScope.launch {
            try {
                val bytes = withContext(Dispatchers.IO) { readCapped(uri) }
                val file = withContext(Dispatchers.Default) { repository.parseBackup(bytes) }
                val preview = repository.previewBackup(file)
                restoreFile = file
                _restore.value = RestoreUi(preview)
            } catch (e: BackupFormatException) {
                messages.trySend("That file is not a Vault backup, or it is incomplete")
            } catch (e: Exception) {
                messages.trySend("Could not read that file")
            }
        }
    }

    fun restore(passphrase: String) {
        val ui = _restore.value ?: return
        val file = restoreFile ?: return
        if (ui.busy || passphrase.isEmpty()) return
        refreshDeviceSecure()
        if (!_create.value.deviceSecure) {
            _restore.value = RestoreUi(ui.preview, message = "Set a screen lock on the phone first.")
            return
        }
        _restore.value = RestoreUi(ui.preview, busy = true)
        viewModelScope.launch {
            val outcome = try {
                repository.restoreBackup(file, PassphraseRules.encode(passphrase))
            } catch (e: Exception) {
                _restore.value = RestoreUi(ui.preview, message = "Could not restore. Nothing was changed.")
                return@launch
            }
            val message = when (outcome) {
                is RestoreOutcome.Restored -> {
                    clearRestore()
                    _screen.value = Screen.List
                    messages.trySend(
                        if (outcome.keptPhoneEntries) "Vault recovered · ${entries(outcome.entryCount)}"
                        else "Restored ${entries(outcome.entryCount)}",
                    )
                    return@launch
                }
                RestoreOutcome.WrongPassphrase -> "Wrong passphrase. Use the passphrase this backup was made with."
                RestoreOutcome.Damaged -> "This backup is damaged or was modified. Nothing was restored."
                RestoreOutcome.Unsupported -> "This backup was made by a newer version of Vault, or it is damaged."
                RestoreOutcome.NotAllowed -> "There is already a vault on this phone."
            }
            _restore.value = RestoreUi(ui.preview, message = message)
        }
    }

    /** Back / Cancel on the restore screen. Ignored while the restore runs. */
    fun cancelRestore() {
        if (_restore.value?.busy == true) return
        clearRestore()
    }

    private fun clearRestore() {
        restoreFile = null
        _restore.value = null
    }

    /** Reads at most [BackupCodec.MAX_FILE_BYTES]; anything larger is not ours. */
    private fun readCapped(uri: Uri): ByteArray {
        val input = app.contentResolver.openInputStream(uri) ?: throw IOException("No stream")
        input.use {
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val n = it.read(buffer)
                if (n < 0) break
                out.write(buffer, 0, n)
                if (out.size() > BackupCodec.MAX_FILE_BYTES) throw BackupFormatException("Too large")
            }
            return out.toByteArray()
        }
    }

    private fun entries(n: Int) = if (n == 1) "1 entry" else "$n entries"

    override fun onCleared() {
        hideSecrets()
        super.onCleared()
    }
}

private const val BIOMETRIC_INVALIDATED =
    "Biometric unlock was turned off because the phone's fingerprints or face data changed. " +
        "Unlock with your passphrase, then turn it on again in Settings."

/** 30 → "30 s", 120 → "2 min". */
internal fun formatSeconds(seconds: Int): String =
    if (seconds >= 60 && seconds % 60 == 0) "${seconds / 60} min" else "$seconds s"

class VaultVmFactory(private val app: VaultApp) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T = VaultViewModel(app) as T
}
