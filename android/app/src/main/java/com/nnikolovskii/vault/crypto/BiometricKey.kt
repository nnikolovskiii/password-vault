package com.nnikolovskii.vault.crypto

import java.security.GeneralSecurityException
import javax.crypto.Cipher

/** The biometric key was invalidated (new fingerprint enrolled, biometrics or screen lock removed). */
class BiometricKeyInvalidatedException : Exception("Biometric key invalidated")

/** No strong biometric is enrolled, or the hardware refuses an auth-bound key. */
class BiometricUnavailableException : Exception("Biometric unavailable")

/**
 * Part 3's second Keystore key: AES-256-GCM, usable only through a `BiometricPrompt` with a
 * `CryptoObject` (auth per use, `BIOMETRIC_STRONG`), invalidated when biometric enrollment
 * changes. It wraps the VK directly:
 *
 * ```
 * VK ─AES-GCM(Keystore "pv.bio.v1", aad = "pv1|<vaultId>|vault|biometric")─▶ vault_meta.biometricWrap
 * ```
 *
 * The ciphers handed out are initialized but not yet authenticated; the prompt authenticates the
 * operation and [BiometricSeal] finishes it. On the phone this is [KeystoreBiometricKey]; the JVM
 * tests use a fake with an ordinary AES key.
 */
interface BiometricKey {
    val alias: String

    /** Replaces any existing key. @throws BiometricUnavailableException */
    fun createKey()

    fun deleteKey()

    fun hasKey(): Boolean

    /** @throws BiometricKeyInvalidatedException */
    fun encryptCipher(): Cipher

    /** @throws BiometricKeyInvalidatedException */
    fun decryptCipher(iv: ByteArray): Cipher
}

/** Blob format for the biometric wrap: `[0x01][iv 12 B][ciphertext ‖ tag 16 B]`, as [Aead]. */
object BiometricSeal {
    /** The IV to initialize the decrypt cipher with. @throws AeadException on a malformed blob. */
    fun iv(blob: ByteArray): ByteArray {
        if (blob.size != Aead.OVERHEAD + KdfParams.KEY_BYTES || blob[0] != Aead.VERSION) throw AeadException()
        return blob.copyOfRange(1, 1 + Aead.NONCE_BYTES)
    }

    /** [cipher]: an authenticated encrypt cipher from [BiometricKey.encryptCipher]. */
    internal fun seal(cipher: Cipher, plaintext: ByteArray, aad: ByteArray): ByteArray {
        cipher.updateAAD(aad)
        val sealed = cipher.doFinal(plaintext)
        val iv = cipher.iv
        check(iv != null && iv.size == Aead.NONCE_BYTES) { "Unexpected IV length" }
        val out = ByteArray(1 + iv.size + sealed.size)
        out[0] = Aead.VERSION
        iv.copyInto(out, 1)
        sealed.copyInto(out, 1 + iv.size)
        return out
    }

    /** The VK, or an [AeadException] when the blob, its AAD, or the key does not match. */
    fun openKey(cipher: Cipher, blob: ByteArray, aad: ByteArray): VaultKey {
        iv(blob)
        val vk = try {
            cipher.updateAAD(aad)
            cipher.doFinal(blob, 1 + Aead.NONCE_BYTES, blob.size - 1 - Aead.NONCE_BYTES)
        } catch (e: GeneralSecurityException) {
            throw AeadException()
        } catch (e: IllegalStateException) {
            throw AeadException()
        }
        if (vk.size != KdfParams.KEY_BYTES) {
            Wipe.bytes(vk)
            throw AeadException()
        }
        return VaultKey(vk)
    }
}
