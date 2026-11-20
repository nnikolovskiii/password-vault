package com.nnikolovskii.vault.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/** Argon2id parameters as stored in the vault header. */
class KdfParams(
    val memoryKib: Int,
    val iterations: Int,
    val parallelism: Int,
    salt: ByteArray,
) {
    private val saltBytes = salt.copyOf()
    val salt: ByteArray get() = saltBytes.copyOf()

    override fun toString(): String = "KdfParams(m=$memoryKib KiB, t=$iterations, p=$parallelism)"

    companion object {
        /** Floor from PLAN.md. Never lower it to make unlock faster. */
        const val MEMORY_KIB = 65_536
        const val MIN_ITERATIONS = 3
        const val MAX_ITERATIONS = 10
        const val PARALLELISM = 1
        const val SALT_BYTES = 16
        const val KEY_BYTES = 32

        /** Upper bounds accepted from a stored header, so a tampered header cannot OOM the app. */
        const val MAX_STORED_MEMORY_KIB = 1_048_576
        const val MAX_STORED_ITERATIONS = 64
        const val MAX_STORED_PARALLELISM = 8
    }
}

/** Passphrase → 32-byte KEK. Pure JVM so the JVM tests run the real thing. */
interface Kdf {
    fun derive(passphrase: ByteArray, params: KdfParams): ByteArray
}

/** Argon2id v1.3 (RFC 9106) through Bouncy Castle's lightweight generator. */
object Argon2Kdf : Kdf {
    override fun derive(passphrase: ByteArray, params: KdfParams): ByteArray {
        val salt = params.salt
        try {
            return raw(
                password = passphrase,
                salt = salt,
                memoryKib = params.memoryKib,
                iterations = params.iterations,
                parallelism = params.parallelism,
                outLength = KdfParams.KEY_BYTES,
            )
        } finally {
            Wipe.bytes(salt)
        }
    }

    /** Full RFC 9106 surface (secret + associated data) so the RFC test vector can run. */
    internal fun raw(
        password: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int,
        outLength: Int,
        secret: ByteArray? = null,
        associatedData: ByteArray? = null,
    ): ByteArray {
        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(memoryKib)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .withSalt(salt)
        if (secret != null) builder.withSecret(secret)
        if (associatedData != null) builder.withAdditional(associatedData)
        val parameters = builder.build()
        val out = ByteArray(outLength)
        try {
            val generator = Argon2BytesGenerator()
            generator.init(parameters)
            generator.generateBytes(password, out)
        } catch (t: Throwable) {
            Wipe.bytes(out)
            throw t
        } finally {
            parameters.clear()
        }
        return out
    }
}
