package com.nnikolovskii.vault.domain

/**
 * User settings (Part 3). Stored as an AEAD blob under the vault key (`vault_meta.settings`,
 * AAD `pv1|<vaultId>|vault|settings`), so nobody with the app's files can stretch the lock
 * timeouts. They are only needed while unlocked, which is exactly when the key is there.
 *
 * Every timeout is a pick from a fixed list; there is no "never". The defaults are the Part 1
 * constants.
 */
class VaultSettings(
    val backgroundLockSeconds: Int = DEFAULT_BACKGROUND_SECONDS,
    val idleLockSeconds: Int = DEFAULT_IDLE_SECONDS,
    val clipboardClearSeconds: Int = DEFAULT_CLIPBOARD_SECONDS,
    val generator: GeneratorOptions = GeneratorOptions(),
) {
    val backgroundLockMillis: Long get() = backgroundLockSeconds * 1_000L
    val idleLockMillis: Long get() = idleLockSeconds * 1_000L
    val clipboardClearMillis: Long get() = clipboardClearSeconds * 1_000L

    fun copy(
        backgroundLockSeconds: Int = this.backgroundLockSeconds,
        idleLockSeconds: Int = this.idleLockSeconds,
        clipboardClearSeconds: Int = this.clipboardClearSeconds,
        generator: GeneratorOptions = this.generator,
    ) = VaultSettings(backgroundLockSeconds, idleLockSeconds, clipboardClearSeconds, generator)

    override fun equals(other: Any?): Boolean =
        other is VaultSettings && backgroundLockSeconds == other.backgroundLockSeconds &&
            idleLockSeconds == other.idleLockSeconds && clipboardClearSeconds == other.clipboardClearSeconds &&
            generator == other.generator

    override fun hashCode(): Int =
        listOf(backgroundLockSeconds, idleLockSeconds, clipboardClearSeconds, generator).hashCode()

    override fun toString(): String =
        "VaultSettings(background=${backgroundLockSeconds}s, idle=${idleLockSeconds}s, clipboard=${clipboardClearSeconds}s)"

    companion object {
        const val DEFAULT_BACKGROUND_SECONDS = (AutoLockPolicy.BACKGROUND_MILLIS / 1_000).toInt()
        const val DEFAULT_IDLE_SECONDS = (AutoLockPolicy.IDLE_MILLIS / 1_000).toInt()
        const val DEFAULT_CLIPBOARD_SECONDS = (ClipboardPolicy.CLEAR_AFTER_MILLIS / 1_000).toInt()

        /**
         * Leaving the app. No "immediately": a lock also clears the clipboard, so a copied
         * password would be gone before it could be pasted.
         */
        val BACKGROUND_CHOICES = listOf(15, 30, 60, 120, 300)
        val IDLE_CHOICES = listOf(60, 120, 300, 600, 900)
        val CLIPBOARD_CHOICES = listOf(10, 15, 30, 60, 120)

        val DEFAULT = VaultSettings()
    }
}

/**
 * Settings payload: version byte, then the same TLV as [EntryCodec]. Unknown tags are skipped and a
 * value outside its choice list falls back to the default, so a later version's blob still opens.
 */
object SettingsCodec {
    const val VERSION: Byte = 0x01

    private const val TAG_BACKGROUND = 1
    private const val TAG_IDLE = 2
    private const val TAG_CLIPBOARD = 3
    private const val TAG_GEN_MODE = 16
    private const val TAG_GEN_LENGTH = 17
    private const val TAG_GEN_SETS = 18
    private const val TAG_GEN_WORDS = 19
    private const val TAG_GEN_SEPARATOR = 20
    private const val TAG_GEN_CAPITALIZE = 21
    private const val TAG_GEN_DIGIT = 22

    private val KNOWN_TAGS = setOf(
        TAG_BACKGROUND, TAG_IDLE, TAG_CLIPBOARD, TAG_GEN_MODE, TAG_GEN_LENGTH, TAG_GEN_SETS,
        TAG_GEN_WORDS, TAG_GEN_SEPARATOR, TAG_GEN_CAPITALIZE, TAG_GEN_DIGIT,
    )

    private const val SET_LOWER = 1
    private const val SET_UPPER = 2
    private const val SET_DIGITS = 4
    private const val SET_SYMBOLS = 8

    fun encode(s: VaultSettings): ByteArray {
        val g = s.generator.sanitized()
        val sets = (if (g.lower) SET_LOWER else 0) or (if (g.upper) SET_UPPER else 0) or
            (if (g.digits) SET_DIGITS else 0) or (if (g.symbols) SET_SYMBOLS else 0)
        return EntryCodec.assemble(
            listOf(
                TAG_BACKGROUND to EntryCodec.varint(s.backgroundLockSeconds.toLong()),
                TAG_IDLE to EntryCodec.varint(s.idleLockSeconds.toLong()),
                TAG_CLIPBOARD to EntryCodec.varint(s.clipboardClearSeconds.toLong()),
                TAG_GEN_MODE to EntryCodec.varint(g.mode.ordinal.toLong()),
                TAG_GEN_LENGTH to EntryCodec.varint(g.length.toLong()),
                TAG_GEN_SETS to EntryCodec.varint(sets.toLong()),
                TAG_GEN_WORDS to EntryCodec.varint(g.words.toLong()),
                TAG_GEN_SEPARATOR to EntryCodec.varint(g.separator.code.toLong()),
                TAG_GEN_CAPITALIZE to EntryCodec.varint(if (g.capitalize) 1 else 0),
                TAG_GEN_DIGIT to EntryCodec.varint(if (g.addDigit) 1 else 0),
            ),
        )
    }

    /** @throws CodecException on a payload that is not a settings blob at all. */
    fun decode(bytes: ByteArray): VaultSettings {
        val d = VaultSettings.DEFAULT
        val dg = d.generator
        var background = d.backgroundLockSeconds
        var idle = d.idleLockSeconds
        var clipboard = d.clipboardClearSeconds
        var mode = dg.mode
        var length = dg.length
        var sets = -1
        var words = dg.words
        var separator = dg.separator
        var capitalize = dg.capitalize
        var digit = dg.addDigit
        EntryCodec.forEachField(bytes) { tag, start, len ->
            // Every field this version knows is a varint; a later version's other fields are skipped.
            if (tag !in KNOWN_TAGS) return@forEachField
            val v = EntryCodec.readVarintValue(bytes, start, len)
            when (tag) {
                TAG_BACKGROUND -> background = pick(v, VaultSettings.BACKGROUND_CHOICES, background)
                TAG_IDLE -> idle = pick(v, VaultSettings.IDLE_CHOICES, idle)
                TAG_CLIPBOARD -> clipboard = pick(v, VaultSettings.CLIPBOARD_CHOICES, clipboard)
                TAG_GEN_MODE -> mode = GeneratorOptions.Mode.entries.getOrNull(v.toInt()) ?: mode
                TAG_GEN_LENGTH -> length = v.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
                TAG_GEN_SETS -> sets = (v and 0x0F).toInt()
                TAG_GEN_WORDS -> words = v.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
                TAG_GEN_SEPARATOR -> separator = if (v in 0..0xFFFF) v.toInt().toChar() else separator
                TAG_GEN_CAPITALIZE -> capitalize = v == 1L
                TAG_GEN_DIGIT -> digit = v == 1L
                else -> Unit
            }
        }
        val generator = GeneratorOptions(
            mode = mode,
            length = length,
            lower = if (sets < 0) dg.lower else sets and SET_LOWER != 0,
            upper = if (sets < 0) dg.upper else sets and SET_UPPER != 0,
            digits = if (sets < 0) dg.digits else sets and SET_DIGITS != 0,
            symbols = if (sets < 0) dg.symbols else sets and SET_SYMBOLS != 0,
            words = words,
            separator = separator,
            capitalize = capitalize,
            addDigit = digit,
        ).sanitized()
        return VaultSettings(background, idle, clipboard, generator)
    }

    private fun pick(value: Long, choices: List<Int>, fallback: Int): Int =
        choices.firstOrNull { it.toLong() == value } ?: fallback
}
