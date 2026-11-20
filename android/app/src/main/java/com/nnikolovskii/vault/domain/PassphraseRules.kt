package com.nnikolovskii.vault.domain

import java.text.Normalizer

/**
 * Passphrase handling: Unicode NFC, then UTF-8, no trimming. The same Cyrillic letter typed on
 * two keyboards (precomposed vs combining) must derive the same key.
 *
 * Create rules: at least [MIN_CODE_POINTS] code points, typed twice, plus the no-recovery
 * acknowledgement. No composition rules.
 */
object PassphraseRules {
    const val MIN_CODE_POINTS = 12

    class Check(val longEnough: Boolean, val matches: Boolean, val acknowledged: Boolean) {
        val ok: Boolean get() = longEnough && matches && acknowledged
    }

    /** NFC → UTF-8 bytes for the KDF. The caller wipes the result. */
    fun encode(passphrase: CharSequence): ByteArray =
        nfc(passphrase).toByteArray(Charsets.UTF_8)

    fun codePoints(passphrase: CharSequence): Int = nfc(passphrase).codePointLength()

    fun check(passphrase: CharSequence, confirm: CharSequence, acknowledged: Boolean): Check =
        Check(
            longEnough = codePoints(passphrase) >= MIN_CODE_POINTS,
            matches = passphrase.isNotEmpty() && nfc(passphrase) == nfc(confirm),
            acknowledged = acknowledged,
        )

    private fun nfc(s: CharSequence): String = Normalizer.normalize(s, Normalizer.Form.NFC)
}
