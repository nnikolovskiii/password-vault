package com.nnikolovskii.vault.ui

import com.nnikolovskii.vault.crypto.BackupCodec
import com.nnikolovskii.vault.crypto.ChangedHeader
import com.nnikolovskii.vault.crypto.CreatedVault
import com.nnikolovskii.vault.crypto.Reauth
import com.nnikolovskii.vault.crypto.UnlockResult
import com.nnikolovskii.vault.data.BiometricEnableStart
import com.nnikolovskii.vault.data.BiometricStart
import com.nnikolovskii.vault.data.EntryEntity
import com.nnikolovskii.vault.data.ExportOutcome
import com.nnikolovskii.vault.domain.EntryDraft
import com.nnikolovskii.vault.domain.EntryRow
import com.nnikolovskii.vault.domain.EntrySecret
import com.nnikolovskii.vault.domain.EntrySummary
import com.nnikolovskii.vault.domain.GeneratorOptions
import com.nnikolovskii.vault.domain.PassphraseRules
import com.nnikolovskii.vault.domain.SummaryPayload
import com.nnikolovskii.vault.domain.toHex
import com.nnikolovskii.vault.session.VaultSession
import com.nnikolovskii.vault.testing.FakeDeviceWrap
import com.nnikolovskii.vault.testing.floorHierarchy
import org.junit.Assert.assertFalse
import org.junit.Test

/** toString() of every secret-holding class must not contain the secret. */
class RedactionTest {
    private val secrets = listOf("Sup3rS3cretPw", "BankTitle", "nikola.user", "bank.example", "private note", "SecretTag")

    private fun assertRedacted(obj: Any) {
        val s = obj.toString()
        for (secret in secrets) assertFalse("${obj.javaClass.simpleName} leaks $secret: $s", s.contains(secret))
    }

    @Test
    fun domainAndUiClassesRedact() {
        val pw = "Sup3rS3cretPw"
        val summary = EntrySummary("id-1", "BankTitle", "nikola.user", "https://bank.example", 1L, 2L, listOf("SecretTag"))
        assertRedacted(summary)
        assertRedacted(SummaryPayload("BankTitle", "nikola.user", "https://bank.example", 1L, 2L))
        assertRedacted(EntrySecret(pw.toCharArray(), "private note".toCharArray()))
        assertRedacted(EntryDraft("BankTitle", "nikola.user", "https://bank.example", pw.toCharArray(), "private note".toCharArray()))
        assertRedacted(EntryRow.Ok(summary))
        assertRedacted(DetailUi(EntryRow.Ok(summary), pw, "private note"))
        assertRedacted(EditForm(id = "id-1", title = "BankTitle", username = "nikola.user", url = "bank.example", password = pw, notes = "private note"))
        assertRedacted(EntryEntity("id-1", 1, ByteArray(64), ByteArray(64)))
        assertRedacted(SummaryPayload("BankTitle", "nikola.user", "https://bank.example", 1L, 2L, listOf("SecretTag")))
        assertRedacted(EntryDraft("BankTitle", "", "", pw.toCharArray(), CharArray(0), listOf("SecretTag")))
        assertRedacted(EditForm(id = null, title = "BankTitle", password = pw, tags = "SecretTag"))
        assertRedacted(GeneratorUi(GeneratorOptions(), pw, 128))
        assertRedacted(BiometricStart.Ready(javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")))
        assertRedacted(BiometricEnableStart.Ready(javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")))
    }

    @Test
    fun keyClassesRedact() {
        val h = floorHierarchy(FakeDeviceWrap())
        val created: CreatedVault = h.create(PassphraseRules.encode("correct horse battery staple"), 0L)
        val vkHex = created.key.copyBytes().toHex()
        for (obj in listOf<Any>(created, created.key, created.header)) {
            assertFalse(obj.toString().contains(vkHex))
            assertFalse(obj.toString().contains("correct horse"))
        }
        val unlocked = h.unlock(created.header, PassphraseRules.encode("correct horse battery staple"))
        assertFalse(unlocked.toString().contains(vkHex))
        assertFalse((unlocked as UnlockResult.Success).key.toString().contains(vkHex))
        val session = VaultSession()
        session.completeUnlock(session.beginUnlock(), unlocked.key, created.header.vaultId)
        session.withKey { assertFalse(it.toString().contains(vkHex)) }
    }

    @Test
    fun backupClassesRedact() {
        val h = floorHierarchy(FakeDeviceWrap())
        val created = h.create(PassphraseRules.encode("correct horse battery staple"), 0L)
        val vkHex = created.key.copyBytes().toHex()
        val proof = h.reauthenticate(created.header, PassphraseRules.encode("correct horse battery staple")) as Reauth.Ok
        val pwWrapHex = proof.pwWrap.toHex()
        val bytes = h.exportFile(created.header, proof, emptyList(), 1L)
        val file = BackupCodec.parse(bytes)
        val opened = h.openBackup(file, PassphraseRules.encode("correct horse battery staple"))
        val ready = ExportOutcome.Ready(bytes, 1L, 0)
        for (obj in listOf<Any>(proof, file, opened, ready, ChangedHeader(created.header, 0L))) {
            val s = obj.toString()
            assertFalse(s, s.contains(vkHex) || s.contains(pwWrapHex) || s.contains("correct horse"))
        }
        assertFalse(PassphraseTaskUi(message = "Wrong passphrase").toString().contains("correct horse"))
    }
}
