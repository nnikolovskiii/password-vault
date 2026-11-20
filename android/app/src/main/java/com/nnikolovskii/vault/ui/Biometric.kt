package com.nnikolovskii.vault.ui

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import javax.crypto.Cipher

/** A prompt the ViewModel wants shown. The cipher is not secret: its key never leaves the Keystore. */
sealed interface BiometricRequest {
    val cipher: Cipher

    class Unlock(override val cipher: Cipher) : BiometricRequest
    class Enable(override val cipher: Cipher) : BiometricRequest
}

sealed interface BiometricResult {
    /** The prompt authenticated [cipher]'s operation; it can now finish once. */
    class Succeeded(val cipher: Cipher) : BiometricResult

    /** Back, "Use passphrase", or the prompt was dismissed by the system. Nothing to say. */
    data object Cancelled : BiometricResult

    /** Lockout, sensor error, …: [message] is the system's own text. */
    class Error(val message: String?) : BiometricResult
}

/**
 * The framework `BiometricPrompt` (API 28+), so no androidx.biometric / Fragment dependency.
 * Only `BIOMETRIC_STRONG` can unlock a `CryptoObject` key, which is what the Keystore key demands.
 */
object BiometricSupport {
    enum class Availability { Available, NoneEnrolled, Unsupported }

    fun availability(context: Context): Availability {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val manager = context.getSystemService(BiometricManager::class.java) ?: return Availability.Unsupported
            return when (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
                BiometricManager.BIOMETRIC_SUCCESS -> Availability.Available
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NoneEnrolled
                else -> Availability.Unsupported
            }
        }
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q) {
            val manager = context.getSystemService(BiometricManager::class.java) ?: return Availability.Unsupported
            @Suppress("DEPRECATION")
            return when (manager.canAuthenticate()) {
                BiometricManager.BIOMETRIC_SUCCESS -> Availability.Available
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NoneEnrolled
                else -> Availability.Unsupported
            }
        }
        // API 28: no BiometricManager. Creating the key fails if nothing is enrolled.
        return if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            Availability.Available
        } else {
            Availability.Unsupported
        }
    }

    /** Shows the prompt; [onResult] runs once, on the main thread. */
    fun prompt(
        activity: Activity,
        title: String,
        negative: String,
        cipher: Cipher,
        cancel: CancellationSignal,
        onResult: (BiometricResult) -> Unit,
    ) {
        val executor = activity.mainExecutor
        var done = false
        val finish = { r: BiometricResult ->
            if (!done) {
                done = true
                onResult(r)
            }
        }
        val builder = BiometricPrompt.Builder(activity)
            .setTitle(title)
            .setNegativeButton(negative, executor) { _, _ -> finish(BiometricResult.Cancelled) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val authenticated = result.cryptoObject?.cipher
                finish(if (authenticated != null) BiometricResult.Succeeded(authenticated) else BiometricResult.Error(null))
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                finish(
                    when (errorCode) {
                        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
                        BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
                        -> BiometricResult.Cancelled
                        else -> BiometricResult.Error(errString?.toString())
                    },
                )
            }
            // onAuthenticationFailed (a finger that does not match): the prompt keeps going.
        }
        try {
            builder.build().authenticate(BiometricPrompt.CryptoObject(cipher), cancel, executor, callback)
        } catch (e: RuntimeException) {
            finish(BiometricResult.Error(null))
        }
    }
}
