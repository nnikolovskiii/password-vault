package com.nnikolovskii.vault.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore AES-256-GCM key `pv.bio.v1` (Part 3): every use needs a fresh
 * `BIOMETRIC_STRONG` authentication through `BiometricPrompt` + `CryptoObject`, and the key is
 * invalidated when a biometric is enrolled (or all are removed, or the screen lock goes).
 * StrongBox when present, else TEE, like [KeystoreDeviceWrap].
 *
 * Not `setUnlockedDeviceRequired`: auth per use with a strong biometric already needs the person
 * at an unlocked phone, and that combination has been unreliable on some Android builds.
 */
class KeystoreBiometricKey(private val context: Context) : BiometricKey {
    override val alias: String = ALIAS

    override fun createKey() {
        deleteKey()
        val wantStrongBox = context.packageManager
            .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        try {
            if (wantStrongBox) {
                try {
                    generate(strongBox = true)
                    return
                } catch (_: StrongBoxUnavailableException) {
                    // Fall through to TEE.
                } catch (_: ProviderException) {
                    deleteKey()
                }
            }
            generate(strongBox = false)
        } catch (e: InvalidAlgorithmParameterException) {
            // No strong biometric enrolled.
            throw BiometricUnavailableException()
        } catch (e: IllegalStateException) {
            throw BiometricUnavailableException()
        } catch (e: ProviderException) {
            throw BiometricUnavailableException()
        }
    }

    override fun deleteKey() {
        try {
            val keyStore = keyStore()
            if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
        } catch (_: GeneralSecurityException) {
        }
    }

    override fun hasKey(): Boolean =
        try {
            keyStore().containsAlias(ALIAS)
        } catch (_: GeneralSecurityException) {
            false
        }

    override fun encryptCipher(): Cipher = cipher { it.init(Cipher.ENCRYPT_MODE, key()) }

    override fun decryptCipher(iv: ByteArray): Cipher =
        cipher { it.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(Aead.TAG_BYTES * 8, iv)) }

    private fun cipher(init: (Cipher) -> Unit): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            init(cipher)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw BiometricKeyInvalidatedException()
        } catch (e: GeneralSecurityException) {
            // Key missing or unusable: the same outcome for the user.
            throw BiometricKeyInvalidatedException()
        }
        return cipher
    }

    private fun key(): SecretKey =
        keyStore().getKey(ALIAS, null) as? SecretKey ?: throw KeyPermanentlyInvalidatedException()

    private fun generate(strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // 0 s = every use needs its own authentication, and only a strong biometric counts.
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            // -1 = auth per use, biometric only (API 28–29).
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(builder.build())
        generator.generateKey()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    companion object {
        const val ALIAS = "pv.bio.v1"
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
