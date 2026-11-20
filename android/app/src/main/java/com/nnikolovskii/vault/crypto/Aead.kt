package com.nnikolovskii.vault.crypto

import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Decryption failed: wrong key, wrong AAD, or edited bytes. Carries no detail on purpose. */
class AeadException(message: String = "Authentication failed") : GeneralSecurityException(message)

/**
 * AES-256-GCM with the vault blob format: `[0x01][nonce 12 B][ciphertext ‖ tag 16 B]`.
 * Random 96-bit nonce per encryption, 128-bit tag.
 */
object Aead {
    const val VERSION: Byte = 0x01
    const val NONCE_BYTES = 12
    const val TAG_BYTES = 16
    const val OVERHEAD = 1 + NONCE_BYTES + TAG_BYTES
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    private val random = SecureRandom()

    /** Wraps raw key bytes. The caller still owns (and wipes) [key]; the spec keeps a copy. */
    fun key(key: ByteArray): SecretKey {
        require(key.size == 32) { "AES-256 key must be 32 bytes" }
        return SecretKeySpec(key, "AES")
    }

    fun encrypt(key: SecretKey, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, nonce))
        cipher.updateAAD(aad)
        val sealed = cipher.doFinal(plaintext)
        val out = ByteArray(1 + NONCE_BYTES + sealed.size)
        out[0] = VERSION
        nonce.copyInto(out, 1)
        sealed.copyInto(out, 1 + NONCE_BYTES)
        return out
    }

    fun decrypt(key: SecretKey, blob: ByteArray, aad: ByteArray): ByteArray {
        if (blob.size < OVERHEAD || blob[0] != VERSION) throw AeadException()
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(TAG_BYTES * 8, blob, 1, NONCE_BYTES),
            )
            cipher.updateAAD(aad)
            return cipher.doFinal(blob, 1 + NONCE_BYTES, blob.size - 1 - NONCE_BYTES)
        } catch (e: GeneralSecurityException) {
            throw AeadException()
        }
    }
}
