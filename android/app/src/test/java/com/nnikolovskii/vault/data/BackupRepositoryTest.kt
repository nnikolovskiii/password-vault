package com.nnikolovskii.vault.data

import com.nnikolovskii.vault.crypto.Aead
import com.nnikolovskii.vault.crypto.BackupFormatException
import com.nnikolovskii.vault.domain.BackupInfo
import com.nnikolovskii.vault.domain.BackupReminder
import com.nnikolovskii.vault.domain.EntryDraft
import com.nnikolovskii.vault.domain.EntryRow
import com.nnikolovskii.vault.domain.PassphraseRules
import com.nnikolovskii.vault.session.SessionState
import com.nnikolovskii.vault.testing.TestVault
import com.nnikolovskii.vault.testing.containsBytes
import com.nnikolovskii.vault.testing.utf8
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Part 2: export → restore, tamper / truncate, change passphrase, Device key lost recovery. */
class BackupRepositoryTest {
    private val pass = "correct horse battery staple"
    private val newPass = "purple elephant ladder ninety"

    private fun draft(title: String, username: String = "", password: String = "", url: String = "", notes: String = "") =
        EntryDraft(title, username, url, password.toCharArray(), notes.toCharArray())

    private suspend fun created(): TestVault {
        val v = TestVault()
        v.repository.refreshRestingState()
        v.repository.createVault(PassphraseRules.encode(pass))
        assertEquals(SessionState.Unlocked, v.session.state.value)
        return v
    }

    /** A new install on a new phone: empty DB, no device key. */
    private suspend fun freshInstall(): TestVault {
        val v = TestVault()
        v.repository.refreshRestingState()
        assertEquals(SessionState.NoVault, v.session.state.value)
        return v
    }

    private suspend fun TestVault.addThree() {
        repository.upsertEntry(null, draft("Bank", "nikola", "s3cret-bank", "https://bank.example"))
        repository.upsertEntry(null, draft("Пошта 📬", "никола", "лозинка-🔐", notes = "long note\n".repeat(400)))
        repository.upsertEntry(null, draft("Router", password = "admin-admin"))
    }

    /** title → username|url|password|notes, for every readable entry. */
    private suspend fun TestVault.snapshot(): Map<String, String> {
        val rows = repository.observeRows().first()
        return rows.filterIsInstance<EntryRow.Ok>().associate { row ->
            val s = row.summary
            val secret = repository.readSecret(s.id)
            s.title to "${s.username}|${s.url}|${String(secret.password)}|${String(secret.notes)}"
        }
    }

    private suspend fun TestVault.export(passphrase: String = pass): ExportOutcome.Ready =
        repository.exportBackup(PassphraseRules.encode(passphrase)) as ExportOutcome.Ready

    private suspend fun TestVault.restore(bytes: ByteArray, passphrase: String = pass): RestoreOutcome =
        repository.restoreBackup(repository.parseBackup(bytes), PassphraseRules.encode(passphrase))

    private suspend fun TestVault.info(): BackupInfo = repository.observeBackupInfo().first()!!

    // --- Export → restore ----------------------------------------------------------------------

    @Test
    fun exportThenRestoreOnAFreshInstallBringsBackEveryEntry() = runBlocking {
        val v = created()
        v.addThree()
        val before = v.snapshot()
        v.now += 1_000
        val ready = v.export()
        assertEquals(3, ready.entryCount)
        assertEquals(v.now, ready.exportedAt)

        val phone = freshInstall()
        val preview = phone.repository.previewBackup(phone.repository.parseBackup(ready.bytes))
        assertEquals(3, preview.entryCount)
        assertEquals(ready.exportedAt, preview.exportedAt)
        assertFalse(preview.keepsPhoneEntries)
        assertFalse(preview.replacesOtherVault)

        val outcome = phone.restore(ready.bytes)
        assertTrue(outcome is RestoreOutcome.Restored)
        assertEquals(3, (outcome as RestoreOutcome.Restored).entryCount)
        assertEquals(SessionState.Unlocked, phone.session.state.value)
        assertEquals(before, phone.snapshot())

        // Same vault id and VK: blobs imported byte for byte. New device wrap.
        val oldMeta = v.metaDao.row!!
        val newMeta = phone.metaDao.row!!
        assertArrayEquals(oldMeta.vaultId, newMeta.vaultId)
        assertArrayEquals(oldMeta.kdfSalt, newMeta.kdfSalt)
        assertFalse(oldMeta.wrappedVaultKey.contentEquals(newMeta.wrappedVaultKey))
        for ((id, e) in v.entryDao.rows.value) {
            val r = phone.entryDao.rows.value[id]!!
            assertArrayEquals(e.summaryBlob, r.summaryBlob)
            assertArrayEquals(e.secretBlob, r.secretBlob)
        }
        // The restored file counts as the last backup.
        val info = phone.info()
        assertEquals(ready.exportedAt, info.lastBackupAt)
        assertFalse(info.changedSinceBackup)

        // Lock, then the restored vault opens like any other.
        phone.session.lock()
        assertEquals(SessionState.Locked, phone.repository.restingState())
        assertTrue(phone.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.Unlocked)
        assertEquals(before, phone.snapshot())
    }

    @Test
    fun exportAsksForThePassphraseAgain() = runBlocking {
        val v = created()
        v.addThree()
        val wrong = v.repository.exportBackup(PassphraseRules.encode("correct horse battery stapler"))
        assertTrue(wrong is ReauthFailure.WrongPassphrase)
        assertEquals(1, v.backoff.value.failures)
        // Still unlocked: a failed export is not a lock.
        assertEquals(SessionState.Unlocked, v.session.state.value)
        val bytes = PassphraseRules.encode(pass)
        assertTrue(v.repository.exportBackup(bytes) is ExportOutcome.Ready)
        assertTrue(bytes.all { it == 0.toByte() })
        assertEquals(0, v.backoff.value.failures)
    }

    @Test
    fun exportHonoursTheBackoff() = runBlocking {
        val v = created()
        repeat(5) { v.repository.exportBackup(PassphraseRules.encode("nope nope nope")) }
        val blocked = v.repository.exportBackup(PassphraseRules.encode(pass))
        assertTrue(blocked is ReauthFailure.BackoffActive)
    }

    @Test
    fun exportFileHoldsNoPlaintextAndNoDeviceLayer() = runBlocking {
        val v = created()
        val words = listOf("UniqueBankTitle", "nikola.user", "Sup3rS3cretPw!", "https://bank.example", "my private note")
        v.repository.upsertEntry(null, draft(words[0], words[1], words[2], words[3], words[4]))
        val file = v.export().bytes
        for (w in words) assertFalse(w, file.containsBytes(utf8(w)))
        assertFalse(file.containsBytes(utf8(pass)))
        // The passphrase wrap is in the file; the device layer is not.
        val meta = v.metaDao.row!!
        assertFalse(file.containsBytes(meta.wrappedVaultKey))
        val pwWrap = v.deviceWrap.unwrap(meta.wrappedVaultKey, meta.vaultId)
        assertTrue(file.containsBytes(pwWrap))
    }

    // --- Tamper / truncate -------------------------------------------------------------------

    @Test
    fun editedEntryBytesAreRejectedAndNothingIsWritten() = runBlocking {
        val v = created()
        v.addThree()
        val file = v.export().bytes
        val phone = freshInstall()
        // A byte inside the last entry's secret blob (just before the 32-byte MAC).
        val edited = file.copyOf().also { it[it.size - 40] = (it[it.size - 40].toInt() xor 0x20).toByte() }
        assertEquals(RestoreOutcome.Damaged, phone.restore(edited))
        assertNull(phone.metaDao.row)
        assertTrue(phone.entryDao.rows.value.isEmpty())
        assertEquals(SessionState.NoVault, phone.session.state.value)
        assertFalse(phone.deviceWrap.hasKey())
    }

    @Test
    fun truncatedFileIsRejected() = runBlocking {
        val v = created()
        v.addThree()
        val file = v.export().bytes
        val phone = freshInstall()
        for (n in listOf(file.size - 1, file.size - 32, file.size - 33, file.size / 2, 100, 8, 0)) {
            try {
                phone.repository.parseBackup(file.copyOf(n))
                fail("truncated to $n bytes parsed")
            } catch (_: BackupFormatException) {
            }
        }
        assertNull(phone.metaDao.row)
    }

    @Test
    fun editedHeaderFailsLikeAWrongPassphrase() = runBlocking {
        val v = created()
        val file = v.export().bytes
        val phone = freshInstall()
        // Offsets: magic 8, vaultId 16, formatVersion 4, alg 1 + 12, m 4, t 4, p 4, salt 1 + 16.
        val saltAt = 8 + 16 + 4 + 1 + 12 + 4 + 4 + 4 + 1
        val salt = file.copyOf().also { it[saltAt] = (it[saltAt] + 1).toByte() }
        assertEquals(RestoreOutcome.WrongPassphrase, phone.restore(salt))
        val tAt = 8 + 16 + 4 + 1 + 12 + 4
        val t = file.copyOf().also { it[tAt + 3] = (it[tAt + 3] + 1).toByte() }
        assertEquals(RestoreOutcome.WrongPassphrase, phone.restore(t))
        // Absurd memory is refused before Argon2id runs (no OOM from a hostile file).
        val mAt = 8 + 16 + 4 + 1 + 12
        val m = file.copyOf().also { it[mAt] = 0x40 }
        assertEquals(RestoreOutcome.Unsupported, phone.restore(m))
        assertNull(phone.metaDao.row)
    }

    @Test
    fun wrongPassphraseOnRestoreChangesNothing() = runBlocking {
        val v = created()
        v.addThree()
        val file = v.export().bytes
        val phone = freshInstall()
        val bytes = PassphraseRules.encode("correct horse battery stapler")
        assertEquals(RestoreOutcome.WrongPassphrase, phone.repository.restoreBackup(phone.repository.parseBackup(file), bytes))
        assertTrue(bytes.all { it == 0.toByte() })
        assertNull(phone.metaDao.row)
        assertEquals(SessionState.NoVault, phone.session.state.value)
        assertTrue(phone.restore(file) is RestoreOutcome.Restored)
    }

    // --- Change passphrase -------------------------------------------------------------------

    @Test
    fun changePassphraseOldFailsNewWorksOldExportStillOpensWithOld() = runBlocking {
        val v = created()
        v.addThree()
        val before = v.snapshot()
        val oldExport = v.export().bytes
        val blobs = v.entryDao.rows.value
        val oldMeta = v.metaDao.row!!

        val current = PassphraseRules.encode(pass)
        val next = PassphraseRules.encode(newPass)
        assertEquals(ChangeOutcome.Changed, v.repository.changePassphrase(current, next))
        assertTrue(current.all { it == 0.toByte() } && next.all { it == 0.toByte() })

        val meta = v.metaDao.row!!
        assertArrayEquals(oldMeta.vaultId, meta.vaultId)
        assertFalse(oldMeta.kdfSalt.contentEquals(meta.kdfSalt))
        assertFalse(oldMeta.wrappedVaultKey.contentEquals(meta.wrappedVaultKey))
        assertArrayEquals(oldMeta.backupInfo, meta.backupInfo)
        // Entries untouched.
        assertEquals(blobs, v.entryDao.rows.value)
        assertEquals(SessionState.Unlocked, v.session.state.value)

        v.session.lock()
        assertTrue(v.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.WrongPassphrase)
        assertTrue(v.repository.unlock(PassphraseRules.encode(newPass)) is UnlockOutcome.Unlocked)
        assertEquals(before, v.snapshot())

        // The old export: new passphrase fails, old one opens it.
        val phone = freshInstall()
        assertEquals(RestoreOutcome.WrongPassphrase, phone.restore(oldExport, newPass))
        assertTrue(phone.restore(oldExport, pass) is RestoreOutcome.Restored)
        assertEquals(before, phone.snapshot())

        // A new export carries the new passphrase.
        val newExport = v.export(newPass).bytes
        val phone2 = freshInstall()
        assertEquals(RestoreOutcome.WrongPassphrase, phone2.restore(newExport, pass))
        assertTrue(phone2.restore(newExport, newPass) is RestoreOutcome.Restored)
    }

    @Test
    fun changePassphraseWithTheWrongCurrentChangesNothing() = runBlocking {
        val v = created()
        val oldMeta = v.metaDao.row!!
        val outcome = v.repository.changePassphrase(PassphraseRules.encode("wrong wrong wrong"), PassphraseRules.encode(newPass))
        assertTrue(outcome is ReauthFailure.WrongPassphrase)
        assertEquals(1, v.backoff.value.failures)
        assertTrue(oldMeta === v.metaDao.row)
        v.session.lock()
        assertTrue(v.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.Unlocked)
    }

    // --- Device key lost recovery ------------------------------------------------------------

    @Test
    fun deviceKeyLostRecoveryKeepsEntriesAddedAfterTheBackup() = runBlocking {
        val v = created()
        val a = v.repository.upsertEntry(null, draft("A", password = "pa"))
        v.repository.upsertEntry(null, draft("B", password = "pb"))
        val file = v.export().bytes
        v.repository.markBackedUp(v.now)
        // After the backup: one new entry, one edit.
        v.repository.upsertEntry(null, draft("C", password = "pc"))
        v.repository.upsertEntry(a, draft("A", password = "pa-edited"))
        val before = v.snapshot()

        v.session.lock()
        v.deviceWrap.lose()
        v.repository.refreshRestingState()
        assertEquals(SessionState.DeviceKeyLost, v.session.state.value)

        val preview = v.repository.previewBackup(v.repository.parseBackup(file))
        assertTrue(preview.keepsPhoneEntries)
        assertFalse(preview.replacesOtherVault)
        assertEquals(2, preview.entryCount)

        val outcome = v.restore(file) as RestoreOutcome.Restored
        assertTrue(outcome.keptPhoneEntries)
        assertEquals(3, outcome.entryCount)
        assertEquals(SessionState.Unlocked, v.session.state.value)
        assertEquals(before, v.snapshot())
        // Changed since the file, so the reminder logic still sees changes.
        assertTrue(v.info().changedSinceBackup)

        v.session.lock()
        assertEquals(SessionState.Locked, v.repository.restingState())
        assertTrue(v.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.Unlocked)
    }

    @Test
    fun deviceKeyLostWithABackupOfAnotherVaultReplacesIt() = runBlocking {
        val mine = created()
        mine.repository.upsertEntry(null, draft("Mine", password = "p1"))
        val file = mine.export().bytes

        val other = created()
        other.repository.upsertEntry(null, draft("Other", password = "p2"))
        other.session.lock()
        other.deviceWrap.lose()
        other.repository.refreshRestingState()

        val preview = other.repository.previewBackup(other.repository.parseBackup(file))
        assertTrue(preview.replacesOtherVault)
        assertFalse(preview.keepsPhoneEntries)
        val outcome = other.restore(file) as RestoreOutcome.Restored
        assertFalse(outcome.keptPhoneEntries)
        assertEquals(setOf("Mine"), other.snapshot().keys)
        assertArrayEquals(mine.metaDao.row!!.vaultId, other.metaDao.row!!.vaultId)
    }

    @Test
    fun restoreIsRefusedWhileAVaultIsOpenOrLocked() = runBlocking {
        val v = created()
        val file = v.export().bytes
        val other = created()
        val meta = other.metaDao.row
        assertEquals(RestoreOutcome.NotAllowed, other.restore(file))
        other.session.lock()
        assertEquals(RestoreOutcome.NotAllowed, other.restore(file))
        assertTrue(meta === other.metaDao.row)
    }

    // --- Last backup / reminder --------------------------------------------------------------

    @Test
    fun backupInfoTracksChangesAndExportsEncrypted() = runBlocking {
        val v = created()
        val fresh = v.info()
        assertNull(fresh.lastBackupAt)
        assertFalse(fresh.changedSinceBackup)

        val id = v.repository.upsertEntry(null, draft("A", password = "pa"))
        assertTrue(v.info().changedSinceBackup)
        assertTrue(BackupReminder.status(v.info(), 1, v.now).remind)

        v.repository.markBackedUp(v.now)
        assertEquals(v.now, v.info().lastBackupAt)
        assertFalse(v.info().changedSinceBackup)
        assertFalse(BackupReminder.status(v.info(), 1, v.now + BackupReminder.REMIND_AFTER_MILLIS).remind)

        v.repository.upsertEntry(id, draft("A", password = "pa2"))
        assertTrue(v.info().changedSinceBackup)
        assertFalse(BackupReminder.status(v.info(), 1, v.now + BackupReminder.REMIND_AFTER_MILLIS - 1).remind)
        assertTrue(BackupReminder.status(v.info(), 1, v.now + BackupReminder.REMIND_AFTER_MILLIS).remind)

        v.repository.markBackedUp(v.now)
        v.repository.deleteEntry(id)
        assertTrue(v.info().changedSinceBackup)

        // Stored as an AEAD blob, bound to this vault.
        val blob = v.metaDao.row!!.backupInfo
        assertNotNull(blob)
        assertEquals(Aead.OVERHEAD + BackupInfo.SIZE, blob!!.size)
        // Locked: nothing to show.
        v.session.lock()
        assertNull(v.repository.observeBackupInfo().first())
    }
}
