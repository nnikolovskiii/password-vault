package com.nnikolovskii.vault.data

import com.nnikolovskii.vault.domain.Backoff
import com.nnikolovskii.vault.domain.EntryDraft
import com.nnikolovskii.vault.domain.EntryRow
import com.nnikolovskii.vault.domain.PassphraseRules
import com.nnikolovskii.vault.session.SessionState
import com.nnikolovskii.vault.session.VaultLockedException
import com.nnikolovskii.vault.testing.TestVault
import com.nnikolovskii.vault.testing.containsBytes
import com.nnikolovskii.vault.testing.utf8
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class VaultRepositoryTest {
    private val pass = "correct horse battery staple"

    private fun draft(title: String, username: String = "", password: String = "", url: String = "", notes: String = "") =
        EntryDraft(title, username, url, password.toCharArray(), notes.toCharArray())

    private suspend fun created(): TestVault {
        val v = TestVault()
        assertEquals(SessionState.NoVault, v.repository.restingState())
        v.repository.createVault(PassphraseRules.encode(pass))
        assertEquals(SessionState.Unlocked, v.session.state.value)
        return v
    }

    private suspend fun TestVault.rows(): List<EntryRow> = repository.observeRows().first()

    @Test
    fun createLockUnlockRightThenWrong() = runBlocking {
        val v = created()
        val id = v.repository.upsertEntry(null, draft("Bank", "nikola", "s3cret"))
        v.session.lock()
        assertEquals(SessionState.Locked, v.session.state.value)
        assertEquals(SessionState.Locked, v.repository.restingState())
        assertTrue(v.rows().isEmpty())

        val wrong = v.repository.unlock(PassphraseRules.encode("correct horse battery stapler"))
        assertTrue(wrong is UnlockOutcome.WrongPassphrase)
        assertEquals(SessionState.Locked, v.session.state.value)
        assertEquals(1, v.backoff.value.failures)

        val right = v.repository.unlock(PassphraseRules.encode(pass))
        assertTrue(right is UnlockOutcome.Unlocked)
        assertEquals(SessionState.Unlocked, v.session.state.value)
        assertEquals(0, v.backoff.value.failures)
        assertEquals("s3cret", String(v.repository.readSecret(id).password))
    }

    @Test
    fun passphraseBytesAreWiped() = runBlocking {
        val v = TestVault()
        val bytes = PassphraseRules.encode(pass)
        v.repository.createVault(bytes)
        assertTrue(bytes.all { it == 0.toByte() })
        v.session.lock()
        val again = PassphraseRules.encode(pass)
        v.repository.unlock(again)
        assertTrue(again.all { it == 0.toByte() })
    }

    @Test
    fun addEditDeleteRoundTrip() = runBlocking {
        val v = created()
        v.now = 1_000L
        val d = draft("Пошта 📬", "никола", "лозинка-🔐", "https://mail.example", "long note\n".repeat(500))
        val id = v.repository.upsertEntry(null, d)
        // Draft secrets are wiped after save.
        assertTrue(d.password.all { it == '\u0000' } && d.notes.all { it == '\u0000' })

        val row = v.repository.readSummary(id) as EntryRow.Ok
        assertEquals("Пошта 📬", row.summary.title)
        assertEquals("никола", row.summary.username)
        assertEquals("https://mail.example", row.summary.url)
        assertEquals(1_000L, row.summary.createdAt)
        val secret = v.repository.readSecret(id)
        assertEquals("лозинка-🔐", String(secret.password))
        assertEquals("long note\n".repeat(500), String(secret.notes))

        v.now = 2_000L
        v.repository.upsertEntry(id, draft("Пошта", "никола", "new-pass"))
        val edited = v.repository.readSummary(id) as EntryRow.Ok
        assertEquals("Пошта", edited.summary.title)
        assertEquals(1_000L, edited.summary.createdAt)
        assertEquals(2_000L, edited.summary.updatedAt)
        assertEquals("new-pass", String(v.repository.readSecret(id).password))
        assertEquals("", String(v.repository.readSecret(id).notes))

        v.repository.deleteEntry(id)
        assertNull(v.entryDao.rows.value[id])
        assertNull(v.repository.readSummary(id))
        assertTrue(v.rows().isEmpty())
    }

    @Test
    fun listIsSortedByTitleCaseInsensitiveWithDamagedLast() = runBlocking {
        val v = created()
        for (t in listOf("zeta", "Alpha", "beta", "Ѓорѓи", "alpha 2")) v.repository.upsertEntry(null, draft(t))
        val other = v.entryDao.rows.value.values.first()
        v.entryDao.put(EntryEntity("damaged-id", 1, other.summaryBlob, other.secretBlob))
        val rows = v.rows()
        val titles = rows.filterIsInstance<EntryRow.Ok>().map { it.summary.title }
        assertEquals(listOf("Alpha", "alpha 2", "beta", "zeta", "Ѓорѓи"), titles)
        assertTrue(rows.last() is EntryRow.Damaged)
        assertEquals("damaged-id", rows.last().id)
    }

    @Test
    fun nothingUserTypedIsStoredInPlaintext() = runBlocking {
        val v = created()
        val words = listOf("UniqueBankTitle", "nikola.user", "Sup3rS3cretPw!", "https://bank.example", "my private note", "Тајна")
        v.repository.upsertEntry(null, draft(words[0], words[1], words[2], words[3], words[4] + " " + words[5]))
        val e = v.entryDao.rows.value.values.single()
        val stored = e.id.toByteArray() + e.summaryBlob + e.secretBlob
        for (w in words) assertFalse(w, stored.containsBytes(utf8(w)))
        // Padded: blob sizes are 1 + 12 + 64k + 16.
        assertEquals(0, (e.summaryBlob.size - 29) % 64)
        assertEquals(0, (e.secretBlob.size - 29) % 64)
        // The header holds no passphrase material either.
        val meta = v.metaDao.row!!
        for (part in listOf(meta.vaultId, meta.kdfSalt, meta.wrappedVaultKey)) {
            assertFalse(part.containsBytes(utf8(pass.substring(0, 8))))
        }
    }

    // --- AAD binding ---------------------------------------------------------------------------

    @Test
    fun summaryBlobMovedToAnotherEntryIsDamaged() = runBlocking {
        val v = created()
        val a = v.repository.upsertEntry(null, draft("A", password = "pa"))
        val b = v.repository.upsertEntry(null, draft("B", password = "pb"))
        val ea = v.entryDao.rows.value[a]!!
        val eb = v.entryDao.rows.value[b]!!
        v.entryDao.put(EntryEntity(b, 1, ea.summaryBlob, eb.secretBlob))
        assertTrue(v.repository.readSummary(b) is EntryRow.Damaged)
        // Secret moved too.
        v.entryDao.put(EntryEntity(b, 1, eb.summaryBlob, ea.secretBlob))
        assertTrue(v.repository.readSummary(b) is EntryRow.Ok)
        expectDamaged { v.repository.readSecret(b) }
    }

    @Test
    fun summarySwappedWithSecretIsDamaged() = runBlocking {
        val v = created()
        val a = v.repository.upsertEntry(null, draft("A", password = "pa"))
        val e = v.entryDao.rows.value[a]!!
        v.entryDao.put(EntryEntity(a, 1, e.secretBlob, e.summaryBlob))
        assertTrue(v.repository.readSummary(a) is EntryRow.Damaged)
        expectDamaged { v.repository.readSecret(a) }
    }

    @Test
    fun blobFromAnotherVaultIsDamaged() = runBlocking {
        val v1 = created()
        val v2 = created()
        val id = v1.repository.upsertEntry(null, draft("Mine", password = "p1"))
        val foreign = v1.entryDao.rows.value[id]!!
        // Same entry id, different vault (different vaultId and VK).
        v2.entryDao.put(foreign)
        assertTrue(v2.repository.readSummary(id) is EntryRow.Damaged)
        expectDamaged { v2.repository.readSecret(id) }
    }

    @Test
    fun editedBlobIsDamaged() = runBlocking {
        val v = created()
        val id = v.repository.upsertEntry(null, draft("A", password = "pa"))
        val e = v.entryDao.rows.value[id]!!
        val flipped = e.summaryBlob.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
        v.entryDao.put(EntryEntity(id, 1, flipped, e.secretBlob))
        assertTrue(v.repository.readSummary(id) is EntryRow.Damaged)
        // Editing a damaged entry is refused (delete only).
        try {
            v.repository.upsertEntry(id, draft("A2"))
            fail("edit of a damaged entry should fail")
        } catch (_: DamagedEntryException) {
        }
    }

    private suspend fun expectDamaged(block: suspend () -> Unit) {
        try {
            block()
            fail("expected DamagedEntryException")
        } catch (_: DamagedEntryException) {
        }
    }

    // --- Session / device / backoff ------------------------------------------------------------

    @Test
    fun lockedRepositoryRefusesEntryWork() = runBlocking {
        val v = created()
        val id = v.repository.upsertEntry(null, draft("A", password = "pa"))
        v.session.lock()
        try {
            v.repository.readSecret(id)
            fail("readSecret while locked")
        } catch (_: VaultLockedException) {
        }
        val d = draft("B", password = "pb")
        try {
            v.repository.upsertEntry(null, d)
            fail("upsert while locked")
        } catch (_: VaultLockedException) {
        }
        assertTrue(d.password.all { it == '\u0000' })
    }

    @Test
    fun lostDeviceKeyMeansDeviceKeyLostStateWithoutAPrompt() = runBlocking {
        val v = created()
        v.session.lock()
        v.deviceWrap.lose()
        assertEquals(SessionState.DeviceKeyLost, v.repository.restingState())
        assertEquals(UnlockOutcome.DeviceKeyLost, v.repository.unlock(PassphraseRules.encode(pass)))
        assertEquals(SessionState.DeviceKeyLost, v.session.state.value)
        // Not counted as a wrong passphrase.
        assertEquals(0, v.backoff.value.failures)
    }

    @Test
    fun backoffBlocksAfterFiveFailuresAndClearsOnSuccess() = runBlocking {
        val v = created()
        v.session.lock()
        repeat(5) {
            assertTrue(v.repository.unlock(PassphraseRules.encode("nope nope nope")) is UnlockOutcome.WrongPassphrase)
        }
        val blocked = v.repository.unlock(PassphraseRules.encode(pass))
        assertTrue(blocked is UnlockOutcome.BackoffActive)
        assertEquals(30_000L, (blocked as UnlockOutcome.BackoffActive).remainingMillis)
        assertEquals(SessionState.Locked, v.session.state.value)

        v.now += 30_000
        assertTrue(v.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.Unlocked)
        assertEquals(0, v.backoff.value.failures)
    }

    @Test
    fun noAutoWipeAfterManyFailures() = runBlocking {
        val v = created()
        val id = v.repository.upsertEntry(null, draft("Keep me", password = "pw"))
        v.session.lock()
        repeat(12) {
            v.backoff.value = Backoff(v.backoff.value.failures, 0L) // skip waiting
            v.repository.unlock(PassphraseRules.encode("wrong wrong wrong"))
        }
        assertNotNull(v.metaDao.row)
        assertNotNull(v.entryDao.rows.value[id])
        v.backoff.value = Backoff()
        assertTrue(v.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.Unlocked)
    }

    @Test
    fun secondVaultCannotBeCreated() = runBlocking {
        val v = created()
        try {
            v.repository.createVault(PassphraseRules.encode("another passphrase here"))
            fail("second create")
        } catch (_: IllegalStateException) {
        }
        assertEquals(SessionState.Unlocked, v.session.state.value)
    }
}
