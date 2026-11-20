package com.nnikolovskii.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test
import java.security.SecureRandom

class AeadTest {
    private val key = Aead.key(ByteArray(32).also(SecureRandom()::nextBytes))
    private val aad = "pv1|aad".toByteArray()
    private val plain = "hunter2 — пароль 🔑".toByteArray()

    private fun assertFails(blob: ByteArray, k: javax.crypto.SecretKey = key, a: ByteArray = aad) {
        try {
            Aead.decrypt(k, blob, a)
            fail("decrypt should have failed")
        } catch (_: AeadException) {
        }
    }

    @Test
    fun roundTrip() {
        val blob = Aead.encrypt(key, plain, aad)
        assertEquals(Aead.VERSION, blob[0])
        assertEquals(plain.size + Aead.OVERHEAD, blob.size)
        assertArrayEquals(plain, Aead.decrypt(key, blob, aad))
    }

    @Test
    fun freshNoncePerEncryption() {
        val a = Aead.encrypt(key, plain, aad)
        val b = Aead.encrypt(key, plain, aad)
        assertFalse(a.copyOfRange(1, 13).contentEquals(b.copyOfRange(1, 13)))
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun bitFlipInNonceFails() {
        val blob = Aead.encrypt(key, plain, aad)
        for (i in 1..Aead.NONCE_BYTES) assertFails(blob.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() })
    }

    @Test
    fun bitFlipInCiphertextFails() {
        val blob = Aead.encrypt(key, plain, aad)
        val start = 1 + Aead.NONCE_BYTES
        for (i in start until blob.size - Aead.TAG_BYTES) {
            assertFails(blob.copyOf().also { it[i] = (it[i].toInt() xor 0x80).toByte() })
        }
    }

    @Test
    fun bitFlipInTagFails() {
        val blob = Aead.encrypt(key, plain, aad)
        for (i in blob.size - Aead.TAG_BYTES until blob.size) {
            assertFails(blob.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() })
        }
    }

    @Test
    fun wrongAadKeyVersionOrLengthFails() {
        val blob = Aead.encrypt(key, plain, aad)
        assertFails(blob, a = "pv1|other".toByteArray())
        assertFails(blob, k = Aead.key(ByteArray(32)))
        assertFails(blob.copyOf().also { it[0] = 0x02 })
        assertFails(blob.copyOf(blob.size - 1))
        assertFails(ByteArray(Aead.OVERHEAD - 1) { 1 })
        assertFails(ByteArray(0))
    }
}
