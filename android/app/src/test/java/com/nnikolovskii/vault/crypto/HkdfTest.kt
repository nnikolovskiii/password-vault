package com.nnikolovskii.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HkdfTest {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** RFC 5869 A.1: basic test case with SHA-256. */
    @Test
    fun rfc5869Case1() {
        val okm = Hkdf.sha256(
            ikm = hex("0b".repeat(22)),
            salt = hex("000102030405060708090a0b0c"),
            info = hex("f0f1f2f3f4f5f6f7f8f9"),
            length = 42,
        )
        assertArrayEquals(
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
            okm,
        )
    }

    /** RFC 5869 A.3: zero-length salt and info. */
    @Test
    fun rfc5869Case3() {
        val okm = Hkdf.sha256(hex("0b".repeat(22)), salt = null, info = ByteArray(0), length = 42)
        assertArrayEquals(
            hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
            okm,
        )
    }

    @Test
    fun exportMacKeyDependsOnTheVaultKeyAndInfo() {
        val vk1 = ByteArray(32) { 1 }
        val vk2 = ByteArray(32) { 2 }
        val k1 = BackupCodec.macKey(vk1)
        assertArrayEquals(k1, BackupCodec.macKey(vk1))
        assertFalse(k1.contentEquals(BackupCodec.macKey(vk2)))
        // Domain separation: not the raw VK, not HKDF with another info.
        assertFalse(k1.contentEquals(vk1))
        assertFalse(k1.contentEquals(Hkdf.sha256(vk1, null, "pv1 other".toByteArray(), 32)))
        assertTrue(Hkdf.equal(k1, BackupCodec.macKey(vk1)))
    }
}
