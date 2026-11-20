package com.nnikolovskii.vault.crypto

import com.nnikolovskii.vault.domain.Aad
import com.nnikolovskii.vault.testing.FakeBiometricKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class BiometricSealTest {
    private val vaultId = ByteArray(16) { it.toByte() }
    private val aad = Aad.biometric(vaultId)

    private fun freshVk() = VaultKey(ByteArray(32) { (it * 7).toByte() })

    private fun expectAead(block: () -> Unit) {
        try {
            block()
            fail("expected AeadException")
        } catch (_: AeadException) {
        }
    }

    @Test
    fun sealOpenRoundTrip() {
        val bio = FakeBiometricKey().also { it.createKey() }
        val vk = freshVk()
        val blob = vk.sealWithBiometric(bio.encryptCipher(), aad)
        assertEquals(Aead.OVERHEAD + 32, blob.size)
        assertEquals(Aead.VERSION, blob[0])
        val opened = BiometricSeal.openKey(bio.decryptCipher(BiometricSeal.iv(blob)), blob, aad)
        assertTrue(opened.sameAs(vk))
    }

    @Test
    fun anotherVaultsAadOrAnotherFieldFails() {
        val bio = FakeBiometricKey().also { it.createKey() }
        val blob = freshVk().sealWithBiometric(bio.encryptCipher(), aad)
        val other = Aad.biometric(ByteArray(16) { 9 })
        expectAead { BiometricSeal.openKey(bio.decryptCipher(BiometricSeal.iv(blob)), blob, other) }
        expectAead { BiometricSeal.openKey(bio.decryptCipher(BiometricSeal.iv(blob)), blob, Aad.settings(vaultId)) }
    }

    @Test
    fun everyBitFlipFails() {
        val bio = FakeBiometricKey().also { it.createKey() }
        val blob = freshVk().sealWithBiometric(bio.encryptCipher(), aad)
        for (i in 1 until blob.size) {
            val bad = blob.copyOf().also { it[i] = (it[i].toInt() xor 0x10).toByte() }
            expectAead { BiometricSeal.openKey(bio.decryptCipher(BiometricSeal.iv(bad)), bad, aad) }
        }
    }

    @Test
    fun aNewKeyCannotOpenTheOldWrap() {
        val bio = FakeBiometricKey().also { it.createKey() }
        val blob = freshVk().sealWithBiometric(bio.encryptCipher(), aad)
        bio.createKey()
        expectAead { BiometricSeal.openKey(bio.decryptCipher(BiometricSeal.iv(blob)), blob, aad) }
    }

    @Test
    fun malformedBlobsAreRejectedBeforeTheCipher() {
        expectAead { BiometricSeal.iv(ByteArray(0)) }
        expectAead { BiometricSeal.iv(ByteArray(Aead.OVERHEAD + 32)) } // version 0
        expectAead { BiometricSeal.iv(ByteArray(Aead.OVERHEAD + 31).also { it[0] = Aead.VERSION }) }
        val ok = ByteArray(Aead.OVERHEAD + 32).also { it[0] = Aead.VERSION; it[1] = 5 }
        assertArrayEquals(ok.copyOfRange(1, 13), BiometricSeal.iv(ok))
    }

    @Test
    fun aWipedKeyCannotBeSealed() {
        val bio = FakeBiometricKey().also { it.createKey() }
        val vk = freshVk()
        vk.wipe()
        try {
            vk.sealWithBiometric(bio.encryptCipher(), aad)
            fail()
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun invalidatedKeyRefusesCiphers() {
        val bio = FakeBiometricKey().also { it.createKey() }
        bio.invalidated = true
        try {
            bio.encryptCipher()
            fail()
        } catch (_: BiometricKeyInvalidatedException) {
        }
    }
}
