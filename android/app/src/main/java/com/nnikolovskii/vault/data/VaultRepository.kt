package com.nnikolovskii.vault.data

import com.nnikolovskii.vault.crypto.Aead
import com.nnikolovskii.vault.crypto.AeadException
import com.nnikolovskii.vault.crypto.BackupCodec
import com.nnikolovskii.vault.crypto.BackupFile
import com.nnikolovskii.vault.crypto.BackupOpen
import com.nnikolovskii.vault.crypto.BiometricKey
import com.nnikolovskii.vault.crypto.BiometricKeyInvalidatedException
import com.nnikolovskii.vault.crypto.BiometricSeal
import com.nnikolovskii.vault.crypto.BiometricUnavailableException
import com.nnikolovskii.vault.crypto.DeviceKeyLostException
import com.nnikolovskii.vault.crypto.DeviceLockedException
import com.nnikolovskii.vault.crypto.DeviceWrap
import com.nnikolovskii.vault.crypto.KeyHierarchy
import com.nnikolovskii.vault.crypto.Reauth
import com.nnikolovskii.vault.crypto.UnlockResult
import com.nnikolovskii.vault.crypto.VaultKey
import com.nnikolovskii.vault.crypto.Wipe
import com.nnikolovskii.vault.domain.Aad
import com.nnikolovskii.vault.domain.Backoff
import com.nnikolovskii.vault.domain.BackupInfo
import com.nnikolovskii.vault.domain.CodecException
import com.nnikolovskii.vault.domain.EntryCodec
import com.nnikolovskii.vault.domain.EntryDraft
import com.nnikolovskii.vault.domain.EntryRow
import com.nnikolovskii.vault.domain.EntrySecret
import com.nnikolovskii.vault.domain.EntrySummary
import com.nnikolovskii.vault.domain.Padding
import com.nnikolovskii.vault.domain.PassphraseSchedule
import com.nnikolovskii.vault.domain.SettingsCodec
import com.nnikolovskii.vault.domain.SummaryPayload
import com.nnikolovskii.vault.domain.VaultSettings
import com.nnikolovskii.vault.session.BackoffStore
import com.nnikolovskii.vault.session.SessionState
import com.nnikolovskii.vault.session.VaultLockedException
import com.nnikolovskii.vault.session.VaultSession
import java.security.GeneralSecurityException
import java.text.Collator
import java.util.UUID
import javax.crypto.Cipher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext

/** An entry's blob would not open (moved, edited, or from another vault). */
class DamagedEntryException(val entryId: String) : Exception("Damaged entry")

sealed interface UnlockOutcome {
    class Unlocked(val kdfMillis: Long) : UnlockOutcome
    class WrongPassphrase(val kdfMillis: Long, val backoff: Backoff) : UnlockOutcome
    class BackoffActive(val remainingMillis: Long) : UnlockOutcome
    data object DeviceKeyLost : UnlockOutcome
    data object DeviceLocked : UnlockOutcome

    /** A lock (screen off etc.) arrived while the KDF was running. */
    data object Interrupted : UnlockOutcome

    /** Biometric: the 7 days since the last passphrase are up. Nothing was opened. */
    data object PassphraseRequired : UnlockOutcome

    /** Biometric: the key was invalidated or the wrap does not open. Biometric is now off. */
    data object BiometricInvalidated : UnlockOutcome
}

/** Lock screen: whether to offer biometric unlock. */
enum class BiometricStatus {
    Off,
    Ready,

    /** On, but 7 days have passed since the passphrase was last typed. */
    PassphraseDue,

    /** Was on; the key is gone or invalidated, so it was just turned off. Reported once. */
    Invalidated,
}

/** Biometric unlock, step 1: a cipher for the prompt's CryptoObject, or why there is none. */
sealed interface BiometricStart {
    class Ready(val cipher: Cipher) : BiometricStart {
        override fun toString(): String = "BiometricStart.Ready"
    }

    data object Off : BiometricStart
    data object PassphraseDue : BiometricStart
    data object Invalidated : BiometricStart
}

/** Export ready: ciphertext only, safe to hand to any SAF destination (Drive included). */
sealed interface ExportOutcome {
    class Ready(val bytes: ByteArray, val exportedAt: Long, val entryCount: Int) : ExportOutcome {
        override fun toString(): String = "ExportOutcome.Ready(entries=$entryCount)"
    }
}

sealed interface ChangeOutcome {
    data object Changed : ChangeOutcome
}

/** Turning biometric on, step 1 (after the passphrase): a cipher for the prompt, or why not. */
sealed interface BiometricEnableStart {
    class Ready(val cipher: Cipher) : BiometricEnableStart {
        override fun toString(): String = "BiometricEnableStart.Ready"
    }

    /** No strong biometric enrolled, or the hardware refused the key. */
    data object Unavailable : BiometricEnableStart
}

/** Why export / change passphrase / biometric setup did not run. Wrong passphrases count toward the backoff. */
sealed interface ReauthFailure : ExportOutcome, ChangeOutcome, BiometricEnableStart {
    class WrongPassphrase(val backoff: Backoff) : ReauthFailure
    class BackoffActive(val remainingMillis: Long) : ReauthFailure
    data object DeviceLocked : ReauthFailure
    data object DeviceKeyLost : ReauthFailure
}

/** What a picked `.pvault` file would do, shown before the passphrase is asked for. */
class BackupPreview(
    /** From the file, not yet authenticated (the MAC needs the passphrase). */
    val exportedAt: Long,
    val entryCount: Int,
    /**
     * Device key lost and the file is a backup of this same vault: the entries already on the
     * phone are kept (they are at least as new), and the file supplies the passphrase layer.
     */
    val keepsPhoneEntries: Boolean,
    /** Device key lost and the file is a different vault: the phone's unreadable vault is replaced. */
    val replacesOtherVault: Boolean,
)

sealed interface RestoreOutcome {
    class Restored(val entryCount: Int, val keptPhoneEntries: Boolean) : RestoreOutcome
    data object WrongPassphrase : RestoreOutcome
    data object Damaged : RestoreOutcome
    data object Unsupported : RestoreOutcome

    /** Restore is only for a fresh install or a Device-key-lost vault. */
    data object NotAllowed : RestoreOutcome
}

/**
 * The only path between Room and plaintext. Every user field is padded and AEAD-encrypted here
 * under the session's vault key, with AAD `pv1|vaultId|entryId|field`. Requires an Unlocked
 * session for anything that touches entries.
 */
class VaultRepository(
    private val metaDao: VaultMetaDao,
    private val entryDao: EntryDao,
    private val hierarchy: KeyHierarchy,
    private val deviceWrap: DeviceWrap,
    private val biometricKey: BiometricKey,
    private val session: VaultSession,
    private val backoffStore: BackoffStore,
    /** Epoch milliseconds, for entry timestamps and the backoff deadline. */
    private val wallClock: () -> Long = System::currentTimeMillis,
    private val newId: () -> String = { UUID.randomUUID().toString() },
    private val kdfDispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val transactor: Transactor = Transactor.Direct,
) {
    private val _settings = MutableStateFlow(VaultSettings.DEFAULT)

    /**
     * Settings of the open vault, decrypted at unlock (before the session reports Unlocked, so
     * auto-lock starts with the right timeouts). Kept after a lock; they are not secret, only
     * tamper-protected at rest.
     */
    val settings: StateFlow<VaultSettings> = _settings.asStateFlow()

    /** Launch / after lock: which resting state the session should be in. */
    suspend fun restingState(): SessionState {
        val meta = metaDao.get() ?: return SessionState.NoVault
        return if (deviceWrap.hasKey() && meta.deviceKeyAlias == deviceWrap.alias) {
            SessionState.Locked
        } else {
            SessionState.DeviceKeyLost
        }
    }

    suspend fun refreshRestingState() {
        if (!session.isUnlocked) session.setResting(restingState())
    }

    /**
     * Creates the vault and leaves the session Unlocked. [passphrase] is NFC UTF-8 bytes; it is
     * wiped here.
     */
    suspend fun createVault(passphrase: ByteArray): Long {
        try {
            check(metaDao.get() == null) { "A vault already exists" }
            val token = session.beginUnlock(announce = false)
            val created = try {
                withContext(kdfDispatcher) { hierarchy.create(passphrase, wallClock()) }
            } catch (t: Throwable) {
                session.setResting(SessionState.NoVault)
                throw t
            }
            try {
                metaDao.insert(VaultMetaEntity.from(created.header))
            } catch (t: Throwable) {
                created.key.wipe()
                session.setResting(SessionState.NoVault)
                throw t
            }
            // A biometric key left from an earlier vault must not outlive it.
            withContext(kdfDispatcher) { biometricKey.deleteKey() }
            backoffStore.save(Backoff())
            _settings.value = VaultSettings.DEFAULT
            if (!session.completeUnlock(token, created.key, created.header.vaultId)) {
                session.setResting(SessionState.Locked)
            }
            notePassphrase(created.header.vaultId)
            return created.kdfMillis
        } finally {
            Wipe.bytes(passphrase)
        }
    }

    /** [passphrase] is NFC UTF-8 bytes; it is wiped here. */
    suspend fun unlock(passphrase: ByteArray): UnlockOutcome {
        try {
            val now = wallClock()
            val backoff = backoffStore.load()
            val remaining = backoff.remainingMillis(now)
            if (remaining > 0) return UnlockOutcome.BackoffActive(remaining)

            val meta = metaDao.get() ?: run {
                session.setResting(SessionState.NoVault)
                return UnlockOutcome.Interrupted
            }
            val header = meta.toHeader()
            val token = session.beginUnlock()
            val result = try {
                withContext(kdfDispatcher) { hierarchy.unlock(header, passphrase) }
            } catch (t: Throwable) {
                session.failUnlock(token)
                throw t
            }
            return when (result) {
                is UnlockResult.Success -> {
                    _settings.value = openSettings(result.key, header.vaultId, meta.settings)
                    if (session.completeUnlock(token, result.key, header.vaultId)) {
                        backoffStore.save(backoff.onSuccess())
                        notePassphrase(header.vaultId)
                        UnlockOutcome.Unlocked(result.kdfMillis)
                    } else {
                        UnlockOutcome.Interrupted
                    }
                }
                is UnlockResult.WrongPassphrase -> {
                    val next = backoff.onFailure(wallClock())
                    backoffStore.save(next)
                    session.failUnlock(token)
                    UnlockOutcome.WrongPassphrase(result.kdfMillis, next)
                }
                UnlockResult.DeviceKeyLost -> {
                    session.setResting(SessionState.DeviceKeyLost)
                    UnlockOutcome.DeviceKeyLost
                }
                UnlockResult.DeviceLocked -> {
                    session.failUnlock(token)
                    UnlockOutcome.DeviceLocked
                }
            }
        } finally {
            Wipe.bytes(passphrase)
        }
    }

    fun backoff(): Backoff = backoffStore.load()

    /**
     * Decrypted list rows, sorted by title (locale collator, case-insensitive). Damaged rows sort
     * last. Emits an empty list while locked.
     */
    fun observeRows(): Flow<List<EntryRow>> =
        combine(entryDao.observeAll(), session.state) { entities, state ->
            if (state != SessionState.Unlocked) emptyList() else decryptRows(entities)
        }

    private fun decryptRows(entities: List<EntryEntity>): List<EntryRow> {
        val rows = try {
            entities.map(::summaryRow)
        } catch (e: IllegalStateException) {
            return emptyList() // Locked mid-way.
        }
        val collator = Collator.getInstance().apply { strength = Collator.SECONDARY }
        return rows.sortedWith(
            compareBy<EntryRow> { it is EntryRow.Damaged }
                .thenComparator { a, b ->
                    if (a is EntryRow.Ok && b is EntryRow.Ok) {
                        collator.compare(a.summary.title, b.summary.title)
                    } else {
                        0
                    }
                }
                .thenBy { it.id },
        )
    }

    suspend fun readSummary(id: String): EntryRow? {
        val entity = entryDao.get(id) ?: return null
        return summaryRow(entity)
    }

    /** Caller wipes the result as soon as it is copied / hidden / saved. */
    suspend fun readSecret(id: String): EntrySecret {
        val entity = entryDao.get(id) ?: throw DamagedEntryException(id)
        return session.withKey { u ->
            val plain = open(u, entity.id, Aad.Field.Secret, entity.secretBlob)
                ?: throw DamagedEntryException(id)
            try {
                EntryCodec.decodeSecret(plain)
            } catch (e: CodecException) {
                throw DamagedEntryException(id)
            } finally {
                Wipe.bytes(plain)
            }
        }
    }

    /**
     * Adds ([id] == null) or replaces an entry. The draft's secret chars are wiped here.
     * @return the entry id.
     * @throws CodecException when a field breaks a limit (message names the field only).
     */
    suspend fun upsertEntry(id: String?, draft: EntryDraft): String {
        try {
            val now = wallClock()
            val entryId = id ?: newId()
            val createdAt = if (id == null) {
                now
            } else {
                when (val existing = readSummary(id)) {
                    is EntryRow.Ok -> existing.summary.createdAt
                    else -> throw DamagedEntryException(id)
                }
            }
            val summaryPlain = EntryCodec.encodeSummary(
                SummaryPayload(draft.title, draft.username, draft.url, createdAt, now, draft.tags),
            )
            val secretPlain = try {
                EntryCodec.encodeSecret(EntrySecret(draft.password, draft.notes))
            } catch (e: Exception) {
                Wipe.bytes(summaryPlain)
                throw e
            }
            val entity = try {
                session.withKey { u ->
                    EntryEntity(
                        id = entryId,
                        formatVersion = EntryEntity.FORMAT_VERSION,
                        summaryBlob = seal(u, entryId, Aad.Field.Summary, summaryPlain),
                        secretBlob = seal(u, entryId, Aad.Field.Secret, secretPlain),
                    )
                }
            } finally {
                Wipe.bytes(summaryPlain, secretPlain)
            }
            transactor.run {
                entryDao.upsert(entity)
                markChanged()
            }
            return entryId
        } finally {
            draft.wipe()
        }
    }

    suspend fun deleteEntry(id: String) {
        transactor.run {
            if (entryDao.delete(id) > 0) markChanged()
        }
    }

    // --- Backup info -------------------------------------------------------------------------

    /** Decrypted backup info while Unlocked; null while locked. */
    fun observeBackupInfo(): Flow<BackupInfo?> =
        combine(metaDao.observe(), session.state) { meta, state ->
            if (state != SessionState.Unlocked || meta == null) {
                null
            } else {
                try {
                    session.withKey { u -> openBackupInfo(u.key, u.vaultId, meta.backupInfo) }
                } catch (e: IllegalStateException) {
                    null // Locked mid-way.
                }
            }
        }

    /** After a `.pvault` file was written: last backup = [exportedAt], nothing changed since. */
    suspend fun markBackedUp(exportedAt: Long) {
        val blob = session.withKey { u -> sealBackupInfo(u.key, u.vaultId, BackupInfo(exportedAt, false)) }
        metaDao.setBackupInfo(blob)
    }

    /** Sets the changed flag (once). Runs inside the entry write's transaction. */
    private suspend fun markChanged() {
        val meta = metaDao.get() ?: return
        val blob = try {
            session.withKey { u ->
                val info = openBackupInfo(u.key, u.vaultId, meta.backupInfo)
                if (info.changedSinceBackup && meta.backupInfo != null) null
                else sealBackupInfo(u.key, u.vaultId, info.withChange())
            }
        } catch (e: VaultLockedException) {
            null // Locked mid-way: the entry write stands, the flag waits for the next change.
        } ?: return
        metaDao.setBackupInfo(blob)
    }

    /** A missing blob is "never"; one that does not open counts as never, changed. */
    private fun openBackupInfo(key: VaultKey, vaultId: ByteArray, blob: ByteArray?): BackupInfo {
        blob ?: return BackupInfo.NONE
        val plain = try {
            Aead.decrypt(key.secretKey(), blob, Aad.backupInfo(vaultId))
        } catch (e: AeadException) {
            return BackupInfo(null, changedSinceBackup = true)
        }
        return try {
            BackupInfo.decode(plain)
        } catch (e: CodecException) {
            BackupInfo(null, changedSinceBackup = true)
        } finally {
            Wipe.bytes(plain)
        }
    }

    private fun sealBackupInfo(key: VaultKey, vaultId: ByteArray, info: BackupInfo): ByteArray {
        val plain = info.encode()
        try {
            return Aead.encrypt(key.secretKey(), plain, Aad.backupInfo(vaultId))
        } finally {
            Wipe.bytes(plain)
        }
    }

    // --- Export / change passphrase ----------------------------------------------------------

    /**
     * Proves [passphrase] again, then builds a `.pvault` file: the header, the passphrase wrap
     * (no device layer), every entry blob as stored, and the whole-file MAC. Wrong passphrases
     * count toward the same backoff as Unlock. [passphrase] is wiped here.
     */
    suspend fun exportBackup(passphrase: ByteArray): ExportOutcome {
        try {
            val (meta, proof) = when (val step = reauthenticate(passphrase)) {
                is Step.Failed -> return step.failure
                is Step.Proven -> step
            }
            try {
                val entries = entryDao.all().map(EntryEntity::toBackup)
                val exportedAt = wallClock()
                val bytes = withContext(kdfDispatcher) {
                    hierarchy.exportFile(meta.toHeader(), proof, entries, exportedAt)
                }
                return ExportOutcome.Ready(bytes, exportedAt, entries.size)
            } finally {
                proof.wipe()
            }
        } finally {
            Wipe.bytes(passphrase)
        }
    }

    /**
     * New salt, re-calibrated `t`, new passphrase wrap of the same VK. Entries and older exports
     * are untouched (an older export still opens with the passphrase it was made with). Both
     * buffers are wiped here.
     */
    suspend fun changePassphrase(current: ByteArray, new: ByteArray): ChangeOutcome {
        try {
            val (meta, proof) = when (val step = reauthenticate(current)) {
                is Step.Failed -> return step.failure
                is Step.Proven -> step
            }
            try {
                val changed = try {
                    withContext(kdfDispatcher) { hierarchy.changePassphrase(meta.toHeader(), proof.key, new) }
                } catch (e: DeviceKeyLostException) {
                    return ReauthFailure.DeviceKeyLost
                } catch (e: DeviceLockedException) {
                    return ReauthFailure.DeviceLocked
                }
                val h = changed.header
                val rows = metaDao.updateKdf(
                    h.kdfAlgorithm, h.kdfSalt, h.kdfMemoryKib, h.kdfIterations, h.kdfParallelism,
                    h.wrappedVaultKey, h.deviceKeyAlias,
                )
                check(rows == 1) { "Vault header missing" }
                return ChangeOutcome.Changed
            } finally {
                proof.wipe()
            }
        } finally {
            Wipe.bytes(current, new)
        }
    }

    private sealed interface Step {
        class Failed(val failure: ReauthFailure) : Step

        class Proven(val meta: VaultMetaEntity, val proof: Reauth.Ok) : Step {
            operator fun component1() = meta
            operator fun component2() = proof
        }
    }

    /** Export and change passphrase: backoff, then device unwrap + Argon2id, then same-VK check. */
    private suspend fun reauthenticate(passphrase: ByteArray): Step {
        val backoff = backoffStore.load()
        val remaining = backoff.remainingMillis(wallClock())
        if (remaining > 0) return Step.Failed(ReauthFailure.BackoffActive(remaining))
        if (!session.isUnlocked) throw VaultLockedException()
        val meta = metaDao.get() ?: throw VaultLockedException()
        val result = withContext(kdfDispatcher) { hierarchy.reauthenticate(meta.toHeader(), passphrase) }
        return when (result) {
            is Reauth.Ok -> {
                val same = try {
                    session.withKey { u -> u.key.sameAs(result.key) }
                } catch (e: VaultLockedException) {
                    result.wipe()
                    throw e
                }
                if (!same) {
                    result.wipe()
                    error("Header does not match the open vault")
                }
                backoffStore.save(backoff.onSuccess())
                notePassphrase(meta.vaultId)
                Step.Proven(meta, result)
            }
            is Reauth.WrongPassphrase -> {
                val next = backoff.onFailure(wallClock())
                backoffStore.save(next)
                Step.Failed(ReauthFailure.WrongPassphrase(next))
            }
            Reauth.DeviceKeyLost -> Step.Failed(ReauthFailure.DeviceKeyLost)
            Reauth.DeviceLocked -> Step.Failed(ReauthFailure.DeviceLocked)
        }
    }

    // --- Restore -----------------------------------------------------------------------------

    /** Structure check of a picked file. @throws BackupFormatException */
    fun parseBackup(bytes: ByteArray): BackupFile = BackupCodec.parse(bytes)

    suspend fun previewBackup(file: BackupFile): BackupPreview {
        val local = metaDao.get()
        val sameVault = local != null && local.vaultId.contentEquals(file.vaultId)
        return BackupPreview(
            exportedAt = file.exportedAt,
            entryCount = file.entryCount,
            keepsPhoneEntries = sameVault,
            replacesOtherVault = local != null && !sameVault,
        )
    }

    /**
     * Restore on a fresh install or from Device key lost: passphrase → VK from the file, MAC
     * check, then a new device key and a new `wrappedVaultKey`. Same VK, so entry blobs import
     * unchanged. Leaves the session Unlocked. [passphrase] is wiped here.
     */
    suspend fun restoreBackup(file: BackupFile, passphrase: ByteArray): RestoreOutcome {
        try {
            val resting = session.state.value
            if (resting != SessionState.NoVault && resting != SessionState.DeviceKeyLost) {
                return RestoreOutcome.NotAllowed
            }
            val token = session.beginUnlock(announce = false)
            val opened = withContext(kdfDispatcher) { hierarchy.openBackup(file, passphrase) }
            val key = when (opened) {
                is BackupOpen.Success -> opened.key
                BackupOpen.WrongPassphrase -> return RestoreOutcome.WrongPassphrase
                BackupOpen.Damaged -> return RestoreOutcome.Damaged
                BackupOpen.Unsupported -> return RestoreOutcome.Unsupported
            }
            val keptPhoneEntries: Boolean
            try {
                val local = metaDao.get()
                if (local != null && resting != SessionState.DeviceKeyLost) {
                    key.wipe()
                    return RestoreOutcome.NotAllowed
                }
                keptPhoneEntries = local != null && local.vaultId.contentEquals(file.vaultId)
                val header = withContext(kdfDispatcher) { hierarchy.adoptBackup(file) }
                // Same vault: the phone's own backup info still opens under the same VK. Entries
                // may have changed since this file, so the flag is set.
                val info = if (keptPhoneEntries) {
                    val phone = openBackupInfo(key, file.vaultId, local!!.backupInfo)
                    BackupInfo(maxOf(phone.lastBackupAt ?: file.exportedAt, file.exportedAt), true)
                } else {
                    BackupInfo(file.exportedAt, changedSinceBackup = false)
                }
                // Same vault: its settings still open under the same VK. Biometric is always off
                // after a restore (new device key, and the old biometric key is deleted below).
                val settingsBlob = if (keptPhoneEntries) local!!.settings else null
                val meta = VaultMetaEntity.from(header, sealBackupInfo(key, file.vaultId, info), settingsBlob)
                _settings.value = openSettings(key, file.vaultId, settingsBlob)
                transactor.run {
                    metaDao.clear()
                    metaDao.insert(meta)
                    if (!keptPhoneEntries) {
                        entryDao.deleteAll()
                        entryDao.insertAll(file.entries.map(EntryEntity::from))
                    }
                }
            } catch (t: Throwable) {
                key.wipe()
                throw t
            }
            withContext(kdfDispatcher) { biometricKey.deleteKey() }
            backoffStore.save(Backoff())
            if (!session.completeUnlock(token, key, file.vaultId)) {
                session.setResting(SessionState.Locked)
            }
            notePassphrase(file.vaultId)
            val count = if (keptPhoneEntries) entryDao.all().size else file.entryCount
            return RestoreOutcome.Restored(count, keptPhoneEntries)
        } finally {
            Wipe.bytes(passphrase)
        }
    }

    // --- Settings ----------------------------------------------------------------------------

    /** Encrypts and stores [new]; auto-lock and the clipboard pick it up from [settings]. */
    suspend fun updateSettings(new: VaultSettings) {
        val blob = session.withKey { u -> sealSettings(u.key, u.vaultId, new) }
        check(metaDao.setSettings(blob) == 1) { "Vault header missing" }
        _settings.value = new
    }

    /** A missing blob, or one that does not open or decode, means the defaults (the Part 1 values). */
    private fun openSettings(key: VaultKey, vaultId: ByteArray, blob: ByteArray?): VaultSettings {
        blob ?: return VaultSettings.DEFAULT
        val padded = try {
            Aead.decrypt(key.secretKey(), blob, Aad.settings(vaultId))
        } catch (e: AeadException) {
            return VaultSettings.DEFAULT
        }
        var plain: ByteArray? = null
        return try {
            plain = Padding.unpad(padded)
            SettingsCodec.decode(plain)
        } catch (e: IllegalArgumentException) {
            VaultSettings.DEFAULT
        } catch (e: CodecException) {
            VaultSettings.DEFAULT
        } finally {
            Wipe.bytes(padded, plain)
        }
    }

    /** Padded like entries, so the blob length does not hint at the chosen values. */
    private fun sealSettings(key: VaultKey, vaultId: ByteArray, settings: VaultSettings): ByteArray {
        val plain = SettingsCodec.encode(settings)
        val padded = Padding.pad(plain)
        try {
            return Aead.encrypt(key.secretKey(), padded, Aad.settings(vaultId))
        } finally {
            Wipe.bytes(plain, padded)
        }
    }

    // --- Biometric unlock --------------------------------------------------------------------

    fun observeBiometricEnabled(): Flow<Boolean> = metaDao.observe().map { it?.biometricWrap != null }

    /** For the lock screen. Clears a wrap whose key has vanished (reported once as [BiometricStatus.Invalidated]). */
    suspend fun biometricStatus(): BiometricStatus {
        val meta = metaDao.get() ?: return BiometricStatus.Off
        meta.biometricWrap ?: return BiometricStatus.Off
        if (!withContext(kdfDispatcher) { biometricKey.hasKey() }) {
            metaDao.setBiometricWrap(null)
            return BiometricStatus.Invalidated
        }
        return if (passphraseDue(meta, lockedCountsAsDue = false)) BiometricStatus.PassphraseDue else BiometricStatus.Ready
    }

    /** Step 1: a decrypt cipher for `BiometricPrompt.CryptoObject`. */
    suspend fun beginBiometricUnlock(): BiometricStart {
        val meta = metaDao.get() ?: return BiometricStart.Off
        val blob = meta.biometricWrap ?: return BiometricStart.Off
        if (passphraseDue(meta, lockedCountsAsDue = false)) return BiometricStart.PassphraseDue
        val iv = try {
            BiometricSeal.iv(blob)
        } catch (e: AeadException) {
            turnOffBiometric()
            return BiometricStart.Invalidated
        }
        return try {
            BiometricStart.Ready(withContext(kdfDispatcher) { biometricKey.decryptCipher(iv) })
        } catch (e: BiometricKeyInvalidatedException) {
            turnOffBiometric()
            BiometricStart.Invalidated
        }
    }

    /**
     * Step 2, with the cipher the prompt authenticated: open the VK and unlock. The 7-day rule is
     * checked again here; the pre-check in step 1 only spares a pointless prompt. Does not touch
     * the passphrase backoff, and does not count as typing the passphrase.
     */
    suspend fun finishBiometricUnlock(cipher: Cipher): UnlockOutcome {
        // A late answer (he typed the passphrase meanwhile) must not touch an open session.
        if (session.state.value != SessionState.Locked) return UnlockOutcome.Interrupted
        val meta = metaDao.get() ?: return UnlockOutcome.Interrupted
        val blob = meta.biometricWrap ?: return UnlockOutcome.BiometricInvalidated
        val due = try {
            passphraseDue(meta, lockedCountsAsDue = true)
        } catch (e: DeviceLockedException) {
            return UnlockOutcome.DeviceLocked
        }
        if (due) return UnlockOutcome.PassphraseRequired
        val token = session.beginUnlock()
        val key = try {
            withContext(kdfDispatcher) { BiometricSeal.openKey(cipher, blob, Aad.biometric(meta.vaultId)) }
        } catch (e: AeadException) {
            session.failUnlock(token)
            turnOffBiometric()
            return UnlockOutcome.BiometricInvalidated
        }
        _settings.value = openSettings(key, meta.vaultId, meta.settings)
        return if (session.completeUnlock(token, key, meta.vaultId)) UnlockOutcome.Unlocked(0) else UnlockOutcome.Interrupted
    }

    /**
     * Turning biometric on proves the passphrase first (so whoever holds an open vault cannot add
     * their own finger), then makes a fresh key. [passphrase] is wiped here.
     */
    suspend fun beginEnableBiometric(passphrase: ByteArray): BiometricEnableStart {
        try {
            val proof = when (val step = reauthenticate(passphrase)) {
                is Step.Failed -> return step.failure
                is Step.Proven -> step.proof
            }
            proof.wipe()
            // The old wrap dies with the old key; never leave one that cannot open.
            metaDao.setBiometricWrap(null)
            return try {
                withContext(kdfDispatcher) {
                    biometricKey.createKey()
                    BiometricEnableStart.Ready(biometricKey.encryptCipher())
                }
            } catch (e: BiometricUnavailableException) {
                BiometricEnableStart.Unavailable
            } catch (e: BiometricKeyInvalidatedException) {
                BiometricEnableStart.Unavailable
            }
        } finally {
            Wipe.bytes(passphrase)
        }
    }

    /** Step 2: wrap the session's VK with the authenticated cipher. False when the cipher refused. */
    suspend fun finishEnableBiometric(cipher: Cipher): Boolean {
        val blob = try {
            // StrongBox operations can take a while: off the main thread.
            withContext(kdfDispatcher) {
                session.withKey { u -> u.key.sealWithBiometric(cipher, Aad.biometric(u.vaultId)) }
            }
        } catch (e: GeneralSecurityException) {
            return false
        } catch (e: VaultLockedException) {
            throw e
        } catch (e: IllegalStateException) {
            return false
        }
        return metaDao.setBiometricWrap(blob) == 1
    }

    suspend fun disableBiometric() {
        turnOffBiometric()
    }

    private suspend fun turnOffBiometric() {
        metaDao.setBiometricWrap(null)
        withContext(kdfDispatcher) { biometricKey.deleteKey() }
    }

    /**
     * Unwraps the last-passphrase time. A missing, unreadable, or device-key-lost record counts as
     * due. A locked phone is transient: [lockedCountsAsDue] false lets the pre-check pass, true
     * rethrows so the caller can say "unlock the phone".
     */
    private suspend fun passphraseDue(meta: VaultMetaEntity, lockedCountsAsDue: Boolean): Boolean {
        val blob = meta.passphraseInfo ?: return true
        val last = try {
            val plain = withContext(kdfDispatcher) { deviceWrap.unwrap(blob, Aad.passphraseInfo(meta.vaultId)) }
            try {
                PassphraseSchedule.decode(plain)
            } finally {
                Wipe.bytes(plain)
            }
        } catch (e: DeviceLockedException) {
            if (lockedCountsAsDue) throw e
            return false
        } catch (e: DeviceKeyLostException) {
            return true
        } catch (e: CodecException) {
            return true
        }
        return PassphraseSchedule.due(last, wallClock())
    }

    /** The passphrase was just proven: restart the 7-day clock for biometric unlock. */
    private suspend fun notePassphrase(vaultId: ByteArray) {
        val plain = PassphraseSchedule.encode(wallClock())
        val blob = try {
            withContext(kdfDispatcher) { deviceWrap.wrap(plain, Aad.passphraseInfo(vaultId)) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Device key trouble: the record stays old, so biometric asks for the passphrase. Safe side.
            return
        } finally {
            Wipe.bytes(plain)
        }
        metaDao.setPassphraseInfo(blob)
    }

    // --- blob helpers ------------------------------------------------------------------------

    private fun summaryRow(entity: EntryEntity): EntryRow = session.withKey { u ->
        val plain = open(u, entity.id, Aad.Field.Summary, entity.summaryBlob)
            ?: return@withKey EntryRow.Damaged(entity.id)
        try {
            val p = EntryCodec.decodeSummary(plain)
            EntryRow.Ok(EntrySummary(entity.id, p.title, p.username, p.url, p.createdAt, p.updatedAt, p.tags))
        } catch (e: CodecException) {
            EntryRow.Damaged(entity.id)
        } finally {
            Wipe.bytes(plain)
        }
    }

    /** Pads, encrypts, and wipes [plaintext]. */
    private fun seal(u: VaultSession.Unlocked, entryId: String, field: Aad.Field, plaintext: ByteArray): ByteArray {
        val padded = Padding.pad(plaintext)
        try {
            return Aead.encrypt(u.key.secretKey(), padded, Aad.entry(u.vaultId, entryId, field))
        } finally {
            Wipe.bytes(padded, plaintext)
        }
    }

    /** @return unpadded plaintext (caller wipes), or null when the blob does not open. */
    private fun open(u: VaultSession.Unlocked, entryId: String, field: Aad.Field, blob: ByteArray): ByteArray? {
        val padded = try {
            Aead.decrypt(u.key.secretKey(), blob, Aad.entry(u.vaultId, entryId, field))
        } catch (e: AeadException) {
            return null
        }
        return try {
            Padding.unpad(padded)
        } catch (e: IllegalArgumentException) {
            null
        } finally {
            Wipe.bytes(padded)
        }
    }
}
