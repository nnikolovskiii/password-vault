package com.nnikolovskii.vault.domain

/**
 * Biometric unlock still needs the passphrase every 7 days, so it stays in memory (a forgotten
 * passphrase is unrecoverable) and a biometric-only path does not stay open forever.
 *
 * "Last passphrase" = the last time the passphrase was proven: unlock, export, change passphrase,
 * turning biometric on, create, or restore. It is stored device-wrapped (`vault_meta
 * .passphraseInfo`, AAD `pv1|<vaultId>|vault|passphrase`), so the Unlock screen can check it before
 * showing a pointless biometric prompt, and it cannot be edited without the Keystore key. It is
 * checked again after the prompt, before the vault opens.
 *
 * Payload: `[0x01][epoch ms int64]`.
 */
object PassphraseSchedule {
    const val MAX_AGE_MILLIS = 7L * 24 * 60 * 60 * 1000

    /** A clock that went back more than this since the last passphrase asks for it again. */
    const val CLOCK_SKEW_MILLIS = 10L * 60 * 1000

    const val VERSION: Byte = 0x01
    const val SIZE = 9

    /** True when the passphrase must be typed before biometric may open the vault. */
    fun due(lastPassphraseAt: Long?, nowMillis: Long): Boolean {
        val last = lastPassphraseAt ?: return true
        val age = nowMillis - last
        return age >= MAX_AGE_MILLIS || age < -CLOCK_SKEW_MILLIS
    }

    fun encode(at: Long): ByteArray {
        val out = ByteArray(SIZE)
        out[0] = VERSION
        var v = at
        for (i in 8 downTo 1) {
            out[i] = (v and 0xFF).toByte()
            v = v ushr 8
        }
        return out
    }

    fun decode(bytes: ByteArray): Long {
        if (bytes.size != SIZE || bytes[0] != VERSION) throw CodecException("Bad passphrase info")
        var v = 0L
        for (i in 1..8) v = (v shl 8) or (bytes[i].toLong() and 0xFF)
        return v
    }
}
