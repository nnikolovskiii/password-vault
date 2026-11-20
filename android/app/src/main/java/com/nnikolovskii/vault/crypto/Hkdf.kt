package com.nnikolovskii.vault.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** HKDF-SHA256 (RFC 5869) and HMAC-SHA256 over platform JCA. Pure JVM. */
object Hkdf {
    const val HASH_BYTES = 32
    private const val ALGORITHM = "HmacSHA256"

    /**
     * Extract-then-expand. An empty or null [salt] means HashLen zero bytes (RFC 5869 § 2.2).
     * The caller wipes the result.
     */
    fun sha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * HASH_BYTES) { "Bad HKDF length" }
        val prk = hmac(if (salt == null || salt.isEmpty()) ByteArray(HASH_BYTES) else salt, ikm)
        val mac = Mac.getInstance(ALGORITHM)
        try {
            mac.init(SecretKeySpec(prk, ALGORITHM))
        } finally {
            Wipe.bytes(prk)
        }
        val out = ByteArray(length)
        var block = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            mac.update(block)
            mac.update(info)
            mac.update(counter.toByte())
            val next = mac.doFinal()
            Wipe.bytes(block)
            block = next
            val n = minOf(block.size, length - pos)
            block.copyInto(out, pos, 0, n)
            pos += n
            counter++
        }
        Wipe.bytes(block)
        return out
    }

    fun hmac(key: ByteArray, data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(key, ALGORITHM))
        mac.update(data, offset, length)
        return mac.doFinal()
    }

    /** Constant-time comparison. */
    fun equal(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
}
