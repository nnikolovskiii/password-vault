package com.nnikolovskii.vault.crypto

import com.nnikolovskii.vault.domain.PassphraseRules
import com.nnikolovskii.vault.testing.FakeDeviceWrap
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ChangePassphraseTest {
    private val old = "correct horse battery staple"
    private val new = "purple elephant ladder ninety"

    @Test
    fun newSaltRecalibratedTSameVaultKey() {
        var t = 3
        val device = FakeDeviceWrap()
        val h = KeyHierarchy(Argon2Kdf, device, chooseIterations = { t }, clock = System::currentTimeMillis)
        val created = h.create(PassphraseRules.encode(old), createdAt = 7L)
        val vk = created.key.copyBytes()
        val keyAlias = device.hasKey()

        t = 4 // The phone re-calibrates at change time.
        val proof = h.reauthenticate(created.header, PassphraseRules.encode(old)) as Reauth.Ok
        val changed = h.changePassphrase(created.header, proof.key, PassphraseRules.encode(new)).header
        proof.wipe()

        assertEquals(4, changed.kdfIterations)
        assertEquals(KdfParams.MEMORY_KIB, changed.kdfMemoryKib)
        assertFalse(changed.kdfSalt.contentEquals(created.header.kdfSalt))
        assertArrayEquals(created.header.vaultId, changed.vaultId)
        assertEquals(7L, changed.createdAt)
        // Same device key, not a new one (a new key would strand the stored wrap on a failed write).
        assertTrue(keyAlias && device.hasKey())
        assertTrue(h.unlock(created.header, PassphraseRules.encode(old)) is UnlockResult.Success)

        val viaNew = h.unlock(changed, PassphraseRules.encode(new))
        assertTrue(viaNew is UnlockResult.Success)
        assertArrayEquals(vk, (viaNew as UnlockResult.Success).key.copyBytes())
        assertTrue(h.unlock(changed, PassphraseRules.encode(old)) is UnlockResult.WrongPassphrase)
    }

    @Test
    fun reauthWithTheWrongPassphraseYieldsNothing() {
        val h = KeyHierarchy(Argon2Kdf, FakeDeviceWrap(), { 3 }, System::currentTimeMillis)
        val created = h.create(PassphraseRules.encode(old), 0L)
        assertTrue(h.reauthenticate(created.header, PassphraseRules.encode(new)) is Reauth.WrongPassphrase)
    }
}
