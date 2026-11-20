package com.nnikolovskii.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class Argon2KdfTest {
    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** RFC 9106 §5.3: Argon2id v0x13, m = 32 KiB, t = 3, p = 4, with secret and AD. */
    @Test
    fun rfc9106Argon2idVector() {
        val tag = Argon2Kdf.raw(
            password = ByteArray(32) { 0x01 },
            salt = ByteArray(16) { 0x02 },
            memoryKib = 32,
            iterations = 3,
            parallelism = 4,
            outLength = 32,
            secret = ByteArray(8) { 0x03 },
            associatedData = ByteArray(12) { 0x04 },
        )
        assertArrayEquals(
            hex("0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59"),
            tag,
        )
    }

    /** Reference implementation (phc-winner-argon2 test.c) vector at our 64 MiB memory, p = 1. */
    @Test
    fun referenceVectorAtFloorMemory() {
        val tag = Argon2Kdf.raw(
            password = "password".toByteArray(),
            salt = "somesalt".toByteArray(),
            memoryKib = 65_536,
            iterations = 2,
            parallelism = 1,
            outLength = 32,
        )
        assertArrayEquals(hex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"), tag)
    }

    @Test
    fun deriveUsesHeaderParamsAndIsDeterministic() {
        val salt = ByteArray(16) { it.toByte() }
        val params = KdfParams(KdfParams.MEMORY_KIB, 3, 1, salt)
        val a = Argon2Kdf.derive("correct horse battery".toByteArray(), params)
        val b = Argon2Kdf.derive("correct horse battery".toByteArray(), params)
        val c = Argon2Kdf.derive("correct horse battery".toByteArray(), KdfParams(KdfParams.MEMORY_KIB, 4, 1, salt))
        assertEquals(32, a.size)
        assertArrayEquals(a, b)
        assertFalse(a.contentEquals(c))
    }

    @Test
    fun paramsCopySaltDefensively() {
        val salt = ByteArray(16) { 7 }
        val params = KdfParams(KdfParams.MEMORY_KIB, 3, 1, salt)
        salt.fill(0)
        params.salt.fill(1)
        assertArrayEquals(ByteArray(16) { 7 }, params.salt)
    }
}
