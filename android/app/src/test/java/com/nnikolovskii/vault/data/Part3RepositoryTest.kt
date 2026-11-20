package com.nnikolovskii.vault.data

import com.nnikolovskii.vault.crypto.Aead
import com.nnikolovskii.vault.crypto.BiometricSeal
import com.nnikolovskii.vault.domain.Aad
import com.nnikolovskii.vault.domain.EntryDraft
import com.nnikolovskii.vault.domain.EntryRow
import com.nnikolovskii.vault.domain.GeneratorOptions
import com.nnikolovskii.vault.domain.PassphraseRules
import com.nnikolovskii.vault.domain.PassphraseSchedule
import com.nnikolovskii.vault.domain.Search
import com.nnikolovskii.vault.domain.VaultSettings
import com.nnikolovskii.vault.session.SessionState
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
import org.junit.Test

/** Part 3: biometric unlock (with a fake Keystore key), the 7-day rule, settings, tags. */
class Part3RepositoryTest {
    private val pass = "correct horse battery staple"
    private val day = 24L * 60 * 60 * 1000

    private suspend fun created(): TestVault {
        val v = TestVault()
        v.repository.refreshRestingState()
        v.repository.createVault(PassphraseRules.encode(pass))
        assertEquals(SessionState.Unlocked, v.session.state.value)
        return v
    }

    /** Both steps of turning biometric on; the fake cipher needs no prompt. */
    private suspend fun TestVault.enableBiometric(passphrase: String = pass): BiometricEnableStart {
        val start = repository.beginEnableBiometric(PassphraseRules.encode(passphrase))
        if (start is BiometricEnableStart.Ready) assertTrue(repository.finishEnableBiometric(start.cipher))
        return start
    }

    private suspend fun TestVault.biometricUnlock(): UnlockOutcome {
        val start = repository.beginBiometricUnlock()
        if (start !is BiometricStart.Ready) return when (start) {
            BiometricStart.PassphraseDue -> UnlockOutcome.PassphraseRequired
            else -> UnlockOutcome.BiometricInvalidated
        }
        return repository.finishBiometricUnlock(start.cipher)
    }

    // --- Biometric ---------------------------------------------------------------------------

    @Test
    fun biometricIsOffUntilTurnedOn() = runBlocking {
        val v = created()
        assertNull(v.metaDao.row!!.biometricWrap)
        assertFalse(v.repository.observeBiometricEnabled().first())
        v.session.lock()
        assertEquals(BiometricStatus.Off, v.repository.biometricStatus())
        assertEquals(BiometricStart.Off, v.repository.beginBiometricUnlock())
    }

    @Test
    fun enableThenLockThenBiometricUnlockOpensTheSameVault() = runBlocking {
        val v = created()
        val id = v.repository.upsertEntry(null, EntryDraft("Bank", "nikola", "", "s3cret".toCharArray(), CharArray(0)))
        assertTrue(v.enableBiometric() is BiometricEnableStart.Ready)
        assertTrue(v.repository.observeBiometricEnabled().first())
        val wrap = v.metaDao.row!!.biometricWrap!!
        // The wrap is ciphertext of the VK, not the VK.
        assertEquals(Aead.OVERHEAD + 32, wrap.size)

        v.session.lock()
        assertEquals(BiometricStatus.Ready, v.repository.biometricStatus())
        val outcome = v.biometricUnlock()
        assertTrue(outcome is UnlockOutcome.Unlocked)
        assertEquals(SessionState.Unlocked, v.session.state.value)
        assertEquals("s3cret", String(v.repository.readSecret(id).password))
    }

    @Test
    fun turningBiometricOnNeedsTheRightPassphraseAndCountsTowardTheBackoff() = runBlocking {
        val v = created()
        val wrong = v.enableBiometric("not the passphrase at all")
        assertTrue(wrong is ReauthFailure.WrongPassphrase)
        assertEquals(1, v.backoff.value.failures)
        assertNull(v.metaDao.row!!.biometricWrap)
        assertEquals(0, v.biometricKey.created)
        assertTrue(v.enableBiometric() is BiometricEnableStart.Ready)
        assertEquals(0, v.backoff.value.failures)
    }

    @Test
    fun noEnrolledBiometricLeavesItOff() = runBlocking {
        val v = created()
        v.biometricKey.available = false
        assertEquals(BiometricEnableStart.Unavailable, v.enableBiometric())
        assertNull(v.metaDao.row!!.biometricWrap)
    }

    @Test
    fun biometricUnlockDoesNotTouchTheBackoffOrRestartTheSevenDays() = runBlocking {
        val v = created()
        v.enableBiometric()
        val info = v.metaDao.row!!.passphraseInfo!!.copyOf()
        v.session.lock()
        v.repository.unlock(PassphraseRules.encode("wrong wrong wrong wrong"))
        v.session.lock()
        v.now += day
        assertTrue(v.biometricUnlock() is UnlockOutcome.Unlocked)
        assertEquals(1, v.backoff.value.failures)
        assertTrue(info.contentEquals(v.metaDao.row!!.passphraseInfo!!))
    }

    @Test
    fun passphraseIsRequiredAgainAfterSevenDays() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.session.lock()

        v.now += 7 * day - 1
        assertEquals(BiometricStatus.Ready, v.repository.biometricStatus())
        assertTrue(v.biometricUnlock() is UnlockOutcome.Unlocked)
        v.session.lock()

        v.now += 1
        assertEquals(BiometricStatus.PassphraseDue, v.repository.biometricStatus())
        assertEquals(BiometricStart.PassphraseDue, v.repository.beginBiometricUnlock())
        assertEquals(SessionState.Locked, v.session.state.value)

        // Typing the passphrase restarts the 7 days, and biometric works again.
        assertTrue(v.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.Unlocked)
        v.session.lock()
        assertEquals(BiometricStatus.Ready, v.repository.biometricStatus())
        assertTrue(v.biometricUnlock() is UnlockOutcome.Unlocked)
    }

    @Test
    fun theSevenDayRuleIsCheckedAgainAfterThePrompt() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.session.lock()
        val start = v.repository.beginBiometricUnlock() as BiometricStart.Ready
        // The prompt sat open across the deadline.
        v.now += 7 * day
        assertEquals(UnlockOutcome.PassphraseRequired, v.repository.finishBiometricUnlock(start.cipher))
        assertEquals(SessionState.Locked, v.session.state.value)
    }

    @Test
    fun aLateBiometricAnswerDoesNotTouchAnOpenSession() = runBlocking {
        val v = created()
        val id = v.repository.upsertEntry(null, EntryDraft("Bank", "", "", "pw".toCharArray(), CharArray(0)))
        v.enableBiometric()
        v.session.lock()
        val start = v.repository.beginBiometricUnlock() as BiometricStart.Ready
        // He typed the passphrase while the prompt was up.
        assertTrue(v.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.Unlocked)
        assertEquals(UnlockOutcome.Interrupted, v.repository.finishBiometricUnlock(start.cipher))
        assertEquals(SessionState.Unlocked, v.session.state.value)
        assertEquals("pw", String(v.repository.readSecret(id).password))
    }

    @Test
    fun exportAndChangePassphraseCountAsProvingThePassphrase() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.now += 6 * day
        v.repository.exportBackup(PassphraseRules.encode(pass))
        v.now += 6 * day
        v.session.lock()
        assertEquals(BiometricStatus.Ready, v.repository.biometricStatus())
    }

    @Test
    fun aClockMovedFarBackAsksForThePassphrase() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.session.lock()
        v.now -= 30 * day
        assertEquals(BiometricStatus.PassphraseDue, v.repository.biometricStatus())
    }

    @Test
    fun aMissingOrForgedPassphraseRecordIsDue() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.session.lock()
        // Someone with file access writes a fresh timestamp without the device key.
        v.metaDao.setPassphraseInfo(Aead.encrypt(Aead.key(ByteArray(32)), PassphraseSchedule.encode(v.now), Aad.passphraseInfo(v.metaDao.row!!.vaultId)))
        assertEquals(BiometricStatus.PassphraseDue, v.repository.biometricStatus())
        v.metaDao.setPassphraseInfo(null)
        assertEquals(BiometricStatus.PassphraseDue, v.repository.biometricStatus())
    }

    @Test
    fun newFingerprintEnrolledTurnsBiometricOffAndNeedsThePassphrase() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.session.lock()
        v.biometricKey.invalidated = true
        assertEquals(BiometricStart.Invalidated, v.repository.beginBiometricUnlock())
        assertNull(v.metaDao.row!!.biometricWrap)
        assertFalse(v.biometricKey.hasKey())
        assertEquals(BiometricStatus.Off, v.repository.biometricStatus())
        assertEquals(SessionState.Locked, v.session.state.value)
        // The passphrase still opens the vault, and biometric can be turned on again.
        assertTrue(v.repository.unlock(PassphraseRules.encode(pass)) is UnlockOutcome.Unlocked)
        assertTrue(v.enableBiometric() is BiometricEnableStart.Ready)
    }

    @Test
    fun aVanishedKeyIsReportedOnceThenOff() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.session.lock()
        v.biometricKey.deleteKey()
        assertEquals(BiometricStatus.Invalidated, v.repository.biometricStatus())
        assertEquals(BiometricStatus.Off, v.repository.biometricStatus())
    }

    @Test
    fun aTamperedOrSwappedWrapDoesNotOpenAndTurnsBiometricOff() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.session.lock()
        val wrap = v.metaDao.row!!.biometricWrap!!
        v.metaDao.setBiometricWrap(wrap.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() })
        assertEquals(UnlockOutcome.BiometricInvalidated, v.biometricUnlock())
        assertEquals(SessionState.Locked, v.session.state.value)
        assertNull(v.metaDao.row!!.biometricWrap)
    }

    @Test
    fun aWrapFromAnotherVaultDoesNotOpenThisOne() = runBlocking {
        val a = created()
        a.enableBiometric()
        val b = TestVault(biometricKey = a.biometricKey)
        b.repository.refreshRestingState()
        b.repository.createVault(PassphraseRules.encode(pass))
        // Same Keystore key (it would be, on one phone), but vault b's id in the AAD.
        a.biometricKey.createKey()
        val cipher = a.biometricKey.encryptCipher()
        val wrapForA = b.session.withKey { u -> u.key.sealWithBiometric(cipher, Aad.biometric(a.metaDao.row!!.vaultId)) }
        b.metaDao.setBiometricWrap(wrapForA)
        b.session.lock()
        val iv = BiometricSeal.iv(wrapForA)
        assertEquals(
            UnlockOutcome.BiometricInvalidated,
            b.repository.finishBiometricUnlock(a.biometricKey.decryptCipher(iv)),
        )
    }

    @Test
    fun turningItOffDeletesTheKey() = runBlocking {
        val v = created()
        v.enableBiometric()
        v.repository.disableBiometric()
        assertNull(v.metaDao.row!!.biometricWrap)
        assertFalse(v.biometricKey.hasKey())
        assertFalse(v.repository.observeBiometricEnabled().first())
    }

    @Test
    fun cancellingThePromptWhileTurningOnLeavesNothingHalfOn() = runBlocking {
        val v = created()
        v.enableBiometric()
        // Second attempt: step 1 runs, the prompt is cancelled, so step 2 never does.
        val start = v.repository.beginEnableBiometric(PassphraseRules.encode(pass))
        assertTrue(start is BiometricEnableStart.Ready)
        assertNull(v.metaDao.row!!.biometricWrap)
        v.repository.disableBiometric()
        v.session.lock()
        assertEquals(BiometricStatus.Off, v.repository.biometricStatus())
    }

    @Test
    fun changePassphraseKeepsBiometricWorking() = runBlocking {
        val v = created()
        v.enableBiometric()
        val newPass = "purple elephant ladder ninety"
        assertEquals(
            ChangeOutcome.Changed,
            v.repository.changePassphrase(PassphraseRules.encode(pass), PassphraseRules.encode(newPass)),
        )
        v.session.lock()
        assertTrue(v.biometricUnlock() is UnlockOutcome.Unlocked)
    }

    @Test
    fun restoreTurnsBiometricOffAndDeletesTheKey() = runBlocking {
        val v = created()
        v.enableBiometric()
        val file = v.repository.exportBackup(PassphraseRules.encode(pass)) as ExportOutcome.Ready
        v.session.lock()
        v.deviceWrap.lose()
        v.repository.refreshRestingState()
        assertEquals(SessionState.DeviceKeyLost, v.session.state.value)
        val restored = v.repository.restoreBackup(v.repository.parseBackup(file.bytes), PassphraseRules.encode(pass))
        assertTrue(restored is RestoreOutcome.Restored)
        assertNull(v.metaDao.row!!.biometricWrap)
        assertFalse(v.biometricKey.hasKey())
        // Restore proved the passphrase: the record is fresh under the new device key.
        assertNotNull(v.metaDao.row!!.passphraseInfo)
    }

    @Test
    fun createDeletesALeftoverBiometricKey() = runBlocking {
        val v = TestVault()
        v.biometricKey.createKey()
        v.repository.refreshRestingState()
        v.repository.createVault(PassphraseRules.encode(pass))
        assertFalse(v.biometricKey.hasKey())
        assertNotNull(v.metaDao.row!!.passphraseInfo)
    }

    // --- Settings ----------------------------------------------------------------------------

    @Test
    fun settingsDefaultUntilChangedThenSurviveALock() = runBlocking {
        val v = created()
        assertEquals(VaultSettings.DEFAULT, v.repository.settings.value)
        assertNull(v.metaDao.row!!.settings)
        val chosen = VaultSettings(
            backgroundLockSeconds = 15,
            idleLockSeconds = 120,
            clipboardClearSeconds = 10,
            generator = GeneratorOptions(mode = GeneratorOptions.Mode.Words, words = 7),
        )
        v.repository.updateSettings(chosen)
        assertEquals(chosen, v.repository.settings.value)

        // A new process: settings come back from the encrypted blob at unlock.
        val again = TestVault(deviceWrap = v.deviceWrap, metaDao = v.metaDao, entryDao = v.entryDao, biometricKey = v.biometricKey)
        again.repository.refreshRestingState()
        assertEquals(VaultSettings.DEFAULT, again.repository.settings.value)
        again.repository.unlock(PassphraseRules.encode(pass))
        assertEquals(chosen, again.repository.settings.value)
    }

    @Test
    fun settingsAreDecryptedBeforeTheSessionReportsUnlocked() = runBlocking {
        val v = created()
        v.repository.updateSettings(VaultSettings(backgroundLockSeconds = 15))
        val fresh = TestVault(deviceWrap = v.deviceWrap, metaDao = v.metaDao, entryDao = v.entryDao)
        fresh.repository.refreshRestingState()
        var seen: Int? = null
        fresh.session.addListener(object : com.nnikolovskii.vault.session.VaultSession.Listener {
            override fun onUnlocked() {
                seen = fresh.repository.settings.value.backgroundLockSeconds
            }
        })
        fresh.repository.unlock(PassphraseRules.encode(pass))
        assertEquals(15, seen)
    }

    @Test
    fun settingsBlobIsPaddedAeadBoundToThisVault() = runBlocking {
        val v = created()
        v.repository.updateSettings(VaultSettings(idleLockSeconds = 900))
        val blob = v.metaDao.row!!.settings!!
        assertEquals(Aead.OVERHEAD + 64, blob.size)
        val wrongAad = Aad.backupInfo(v.metaDao.row!!.vaultId)
        v.session.withKey { u ->
            try {
                Aead.decrypt(u.key.secretKey(), blob, wrongAad)
                error("opened under the wrong AAD")
            } catch (_: com.nnikolovskii.vault.crypto.AeadException) {
            }
        }
    }

    @Test
    fun aTamperedSettingsBlobFallsBackToDefaults() = runBlocking {
        val v = created()
        v.repository.updateSettings(VaultSettings(idleLockSeconds = 900))
        val blob = v.metaDao.row!!.settings!!
        v.metaDao.setSettings(blob.copyOf().also { it[30] = (it[30].toInt() xor 1).toByte() })
        v.session.lock()
        v.repository.unlock(PassphraseRules.encode(pass))
        assertEquals(VaultSettings.DEFAULT, v.repository.settings.value)
    }

    @Test
    fun settingsNeedAnOpenVault() = runBlocking {
        val v = created()
        v.session.lock()
        try {
            v.repository.updateSettings(VaultSettings(idleLockSeconds = 900))
            error("updated while locked")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun sameVaultRestoreKeepsSettingsOtherVaultGetsDefaults() = runBlocking {
        val v = created()
        v.repository.updateSettings(VaultSettings(clipboardClearSeconds = 120))
        val file = v.repository.exportBackup(PassphraseRules.encode(pass)) as ExportOutcome.Ready
        v.session.lock()
        v.deviceWrap.lose()
        v.repository.refreshRestingState()
        v.repository.restoreBackup(v.repository.parseBackup(file.bytes), PassphraseRules.encode(pass))
        assertEquals(120, v.repository.settings.value.clipboardClearSeconds)

        val other = TestVault()
        other.repository.refreshRestingState()
        other.repository.restoreBackup(other.repository.parseBackup(file.bytes), PassphraseRules.encode(pass))
        assertEquals(VaultSettings.DEFAULT, other.repository.settings.value)
    }

    // --- Tags + search -----------------------------------------------------------------------

    @Test
    fun tagsAreStoredInsideTheEncryptedSummary() = runBlocking {
        val v = created()
        val id = v.repository.upsertEntry(
            null,
            EntryDraft("Bank", "nikola", "", "pw".toCharArray(), CharArray(0), listOf("money", "РаботаTag")),
        )
        val row = v.repository.readSummary(id) as EntryRow.Ok
        assertEquals(listOf("money", "РаботаTag"), row.summary.tags)
        val stored = v.entryDao.get(id)!!
        assertFalse(stored.summaryBlob.containsBytes(utf8("РаботаTag")))
        assertFalse(stored.summaryBlob.containsBytes(utf8("money")))
        // Editing keeps or replaces tags like any other field.
        v.repository.upsertEntry(id, EntryDraft("Bank", "nikola", "", "pw".toCharArray(), CharArray(0), listOf("money")))
        assertEquals(listOf("money"), (v.repository.readSummary(id) as EntryRow.Ok).summary.tags)
    }

    @Test
    fun searchRunsOverDecryptedRowsOnly() = runBlocking {
        val v = created()
        v.repository.upsertEntry(null, EntryDraft("GMail", "me@gmail.com", "", CharArray(0), CharArray(0), listOf("mail")))
        v.repository.upsertEntry(null, EntryDraft("Bank", "nikola", "", CharArray(0), CharArray(0)))
        val rows = v.repository.observeRows().first()
        assertEquals(listOf("GMail"), Search.filter(rows, "gmail").map { (it as EntryRow.Ok).summary.title })
        v.session.lock()
        // Locked: nothing decrypted, nothing to search.
        assertTrue(Search.filter(v.repository.observeRows().first(), "gmail").isEmpty())
    }
}
