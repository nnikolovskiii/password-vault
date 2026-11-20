package com.nnikolovskii.vault.crypto

import com.nnikolovskii.vault.domain.PassphraseRules
import com.nnikolovskii.vault.testing.FakeDeviceWrap
import com.nnikolovskii.vault.testing.floorHierarchy
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

class KeyHierarchyTest {
    companion object {
        private const val PASS = "correct horse battery staple"
        private lateinit var device: FakeDeviceWrap
        private lateinit var hierarchy: KeyHierarchy
        private lateinit var created: CreatedVault
        private lateinit var vk: ByteArray

        /** One create (real Argon2id at the floor) shared by the tamper tests. */
        @BeforeClass
        @JvmStatic
        fun createVault() {
            device = FakeDeviceWrap()
            hierarchy = floorHierarchy(device)
            created = hierarchy.create(PassphraseRules.encode(PASS), createdAt = 42L)
            vk = created.key.copyBytes()
        }
    }

    private fun unlock(header: VaultHeader = created.header, pass: String = PASS) =
        hierarchy.unlock(header, PassphraseRules.encode(pass))

    @Test
    fun headerHasFloorParams() {
        val h = created.header
        assertEquals(1, h.formatVersion)
        assertEquals("argon2id-v19", h.kdfAlgorithm)
        assertEquals(65_536, h.kdfMemoryKib)
        assertTrue(h.kdfIterations >= 3)
        assertEquals(1, h.kdfParallelism)
        assertEquals(16, h.kdfSalt.size)
        assertEquals(16, h.vaultId.size)
        assertEquals("pv.device.v1", h.deviceKeyAlias)
        assertEquals(42L, h.createdAt)
        // [0x01][nonce 12][pwWrap 61 = 1 + 12 + 32 + 16][tag 16]
        assertEquals(1 + 12 + 61 + 16, h.wrappedVaultKey.size)
    }

    @Test
    fun rightPassphraseUnlocksSameKey() {
        val result = unlock()
        assertTrue(result is UnlockResult.Success)
        assertArrayEquals(vk, (result as UnlockResult.Success).key.copyBytes())
    }

    @Test
    fun wrongPassphraseFails() {
        assertTrue(unlock(pass = "correct horse battery stapl") is UnlockResult.WrongPassphrase)
        assertTrue(unlock(pass = "Correct horse battery staple") is UnlockResult.WrongPassphrase)
    }

    @Test
    fun leadingAndTrailingSpacesAreSignificant() {
        assertTrue(unlock(pass = " $PASS") is UnlockResult.WrongPassphrase)
        assertTrue(unlock(pass = "$PASS ") is UnlockResult.WrongPassphrase)
    }

    @Test
    fun tamperedSaltFails() {
        val salt = created.header.kdfSalt.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertTrue(unlock(created.header.copy(kdfSalt = salt)) is UnlockResult.WrongPassphrase)
    }

    @Test
    fun tamperedIterationsFail() {
        val h = created.header
        assertTrue(unlock(h.copy(kdfIterations = h.kdfIterations + 1)) is UnlockResult.WrongPassphrase)
        // Downgrade below the floor: AAD binds t, so this fails too.
        assertTrue(unlock(h.copy(kdfIterations = 1)) is UnlockResult.WrongPassphrase)
    }

    @Test
    fun tamperedMemoryFails() {
        val h = created.header
        assertTrue(unlock(h.copy(kdfMemoryKib = 32_768)) is UnlockResult.WrongPassphrase)
        // Absurd memory is refused before the KDF runs (no OOM from a tampered header).
        assertTrue(unlock(h.copy(kdfMemoryKib = Int.MAX_VALUE)) is UnlockResult.WrongPassphrase)
    }

    @Test
    fun tamperedVersionOrAlgorithmFails() {
        val h = created.header
        assertTrue(unlock(h.copy(formatVersion = 2)) is UnlockResult.WrongPassphrase)
        assertTrue(unlock(h.copy(kdfAlgorithm = "argon2id-v16")) is UnlockResult.WrongPassphrase)
        assertTrue(unlock(h.copy(kdfAlgorithm = "argon2i-v19")) is UnlockResult.WrongPassphrase)
        assertTrue(unlock(h.copy(kdfParallelism = 2)) is UnlockResult.WrongPassphrase)
    }

    @Test
    fun deviceWrapIsBoundToVaultId() {
        val other = created.header.vaultId.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertEquals(UnlockResult.DeviceKeyLost, unlock(created.header.copy(vaultId = other)))
    }

    @Test
    fun noDeviceKeyNoUnlockEvenWithThePassphrase() {
        // Same files, different phone: a fresh device key cannot open the wrap.
        val otherPhone = FakeDeviceWrap().also { it.createKey() }
        val elsewhere = floorHierarchy(otherPhone)
        assertEquals(UnlockResult.DeviceKeyLost, elsewhere.unlock(created.header, PassphraseRules.encode(PASS)))
        // And no key at all.
        val noKey = floorHierarchy(FakeDeviceWrap())
        assertEquals(UnlockResult.DeviceKeyLost, noKey.unlock(created.header, PassphraseRules.encode(PASS)))
    }

    @Test
    fun deviceLayerAloneDoesNotRevealTheVaultKey() {
        // With the device key but not the passphrase, only pwWrap comes out: VK is not in it.
        val pwWrap = device.unwrap(created.header.wrappedVaultKey, created.header.vaultId)
        assertEquals(61, pwWrap.size)
        for (i in 0..pwWrap.size - vk.size) {
            assertFalse(pwWrap.copyOfRange(i, i + vk.size).contentEquals(vk))
        }
    }

    @Test
    fun passphraseBufferIsWipedByTheCaller() {
        val bytes = PassphraseRules.encode(PASS)
        val result = hierarchy.unlock(created.header, bytes)
        assertTrue(result is UnlockResult.Success)
        // KeyHierarchy does not keep a reference; the repository wipes. Check that wiping is safe.
        Wipe.bytes(bytes)
        assertTrue(bytes.all { it == 0.toByte() })
        val key = (result as UnlockResult.Success).key
        key.wipe()
        assertTrue(key.isWiped)
        assertTrue(key.copyBytes().all { it == 0.toByte() })
    }

    @Test
    fun nfcPrecomposedAndDecomposedCyrillicUnlockTheSameVault() {
        val dev = FakeDeviceWrap()
        val h = floorHierarchy(dev)
        // ѓ precomposed (U+0453) vs г + combining acute (U+0433 U+0301); ќ likewise.
        val precomposed = "ѓораст ќерка лозинка"
        val decomposed = "ѓораст ќерка лозинка"
        val vault = h.create(PassphraseRules.encode(precomposed), 0L)
        val viaDecomposed = h.unlock(vault.header, PassphraseRules.encode(decomposed))
        assertTrue(viaDecomposed is UnlockResult.Success)
        assertArrayEquals(vault.key.copyBytes(), (viaDecomposed as UnlockResult.Success).key.copyBytes())
    }
}
