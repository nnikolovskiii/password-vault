package com.nnikolovskii.vault.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore AES-256-GCM key `pv.device.v1`: non-exportable, StrongBox when present
 * (else TEE), usable only while the phone is unlocked. No user-auth requirement; biometric
 * unlock is Part 3's separate key.
 *
 * Blob: `[0x01][iv 12 B][ciphertext ‖ tag 16 B]` (the Keystore picks the IV).
 *
 * The only class in `crypto/` that touches Android.
 */
class KeystoreDeviceWrap(private val context: Context) : DeviceWrap {
    override val alias: String = ALIAS

    /** True when the key that exists was created in StrongBox (diagnostics only). */
    var strongBox: Boolean = false
        private set

    override fun createKey() {
        val keyStore = keyStore()
        if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
        val wantStrongBox = context.packageManager
            .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (wantStrongBox) {
            try {
                generate(strongBox = true)
                strongBox = true
                return
            } catch (_: StrongBoxUnavailableException) {
                // Fall through to TEE.
            } catch (_: ProviderException) {
                // Some StrongBox chips reject a parameter instead: fall through to TEE.
                if (keyStore().containsAlias(ALIAS)) keyStore().deleteEntry(ALIAS)
            }
        }
        generate(strongBox = false)
        strongBox = false
    }

    override fun hasKey(): Boolean =
        try {
            keyStore().containsAlias(ALIAS)
        } catch (_: GeneralSecurityException) {
            false
        }

    override fun wrap(plaintext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(aad)
        val sealed = cipher.doFinal(plaintext)
        val iv = cipher.iv
        check(iv.size == Aead.NONCE_BYTES) { "Unexpected IV length" }
        val out = ByteArray(1 + iv.size + sealed.size)
        out[0] = Aead.VERSION
        iv.copyInto(out, 1)
        sealed.copyInto(out, 1 + iv.size)
        return out
    }

    override fun unwrap(blob: ByteArray, aad: ByteArray): ByteArray {
        if (blob.size < Aead.OVERHEAD || blob[0] != Aead.VERSION) throw DeviceKeyLostException()
        val key = try {
            key()
        } catch (e: GeneralSecurityException) {
            throw DeviceKeyLostException()
        }
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(Aead.TAG_BYTES * 8, blob, 1, Aead.NONCE_BYTES),
            )
            cipher.updateAAD(aad)
            return cipher.doFinal(blob, 1 + Aead.NONCE_BYTES, blob.size - 1 - Aead.NONCE_BYTES)
        } catch (e: AEADBadTagException) {
            // A different key under the same alias (or an edited wrap): the old key is gone.
            throw DeviceKeyLostException()
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw DeviceKeyLostException()
        } catch (e: UserNotAuthenticatedException) {
            // setUnlockedDeviceRequired: the phone is locked right now. Transient, not lost.
            throw DeviceLockedException()
        }
    }

    private fun key(): SecretKey {
        val entry = keyStore().getKey(ALIAS, null) ?: throw DeviceKeyLostException()
        return entry as SecretKey
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUnlockedDeviceRequired(true)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(spec)
        generator.generateKey()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    companion object {
        const val ALIAS = "pv.device.v1"
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
