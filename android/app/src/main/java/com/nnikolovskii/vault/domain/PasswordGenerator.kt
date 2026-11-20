package com.nnikolovskii.vault.domain

import java.io.IOException
import java.security.SecureRandom
import java.util.Random
import kotlin.math.ln

/** What the generator makes. Remembered in the encrypted settings blob, never plaintext. */
class GeneratorOptions(
    val mode: Mode = Mode.Characters,
    /** Characters mode. */
    val length: Int = DEFAULT_LENGTH,
    val lower: Boolean = true,
    val upper: Boolean = true,
    val digits: Boolean = true,
    val symbols: Boolean = true,
    /** Words mode. */
    val words: Int = DEFAULT_WORDS,
    val separator: Char = '-',
    val capitalize: Boolean = false,
    /** Words mode: one random digit after one random word (for sites that insist on a digit). */
    val addDigit: Boolean = false,
) {
    enum class Mode { Characters, Words }

    /** Out-of-range values come back to the nearest valid one; an empty set list means all sets. */
    fun sanitized(): GeneratorOptions {
        val anySet = lower || upper || digits || symbols
        return GeneratorOptions(
            mode = mode,
            length = length.coerceIn(MIN_LENGTH, MAX_LENGTH),
            lower = lower || !anySet,
            upper = upper || !anySet,
            digits = digits || !anySet,
            symbols = symbols || !anySet,
            words = words.coerceIn(MIN_WORDS, MAX_WORDS),
            separator = if (separator in SEPARATORS) separator else '-',
            capitalize = capitalize,
            addDigit = addDigit,
        )
    }

    fun copy(
        mode: Mode = this.mode,
        length: Int = this.length,
        lower: Boolean = this.lower,
        upper: Boolean = this.upper,
        digits: Boolean = this.digits,
        symbols: Boolean = this.symbols,
        words: Int = this.words,
        separator: Char = this.separator,
        capitalize: Boolean = this.capitalize,
        addDigit: Boolean = this.addDigit,
    ) = GeneratorOptions(mode, length, lower, upper, digits, symbols, words, separator, capitalize, addDigit)

    override fun equals(other: Any?): Boolean =
        other is GeneratorOptions && mode == other.mode && length == other.length &&
            lower == other.lower && upper == other.upper && digits == other.digits &&
            symbols == other.symbols && words == other.words && separator == other.separator &&
            capitalize == other.capitalize && addDigit == other.addDigit

    override fun hashCode(): Int = listOf(mode, length, lower, upper, digits, symbols, words, separator, capitalize, addDigit).hashCode()

    override fun toString(): String = "GeneratorOptions($mode, length=$length, words=$words)"

    companion object {
        const val MIN_LENGTH = 8
        const val MAX_LENGTH = 64
        const val DEFAULT_LENGTH = 20
        const val MIN_WORDS = 4
        const val MAX_WORDS = 10
        const val DEFAULT_WORDS = 6

        /** Word separators offered in the UI. */
        const val SEPARATORS = "-. _"
    }
}

/**
 * Passwords and passphrases from [SecureRandom]. Every pick is uniform (`Random.nextInt(bound)`
 * rejects the biased tail). Characters mode guarantees one character from every chosen set by
 * regenerating until it holds, which keeps the result uniform over all valid passwords. Words
 * mode draws from the EFF large wordlist (7 776 words, 12.9 bits each).
 *
 * Results are CharArrays for the caller to wipe; the edit form still turns them into a String.
 */
class PasswordGenerator(
    private val wordlist: () -> List<String> = EffWordlist::words,
    private val random: Random = SecureRandom(),
) {
    fun generate(options: GeneratorOptions): CharArray {
        val o = options.sanitized()
        return when (o.mode) {
            GeneratorOptions.Mode.Characters -> characters(o)
            GeneratorOptions.Mode.Words -> words(o)
        }
    }

    private fun characters(o: GeneratorOptions): CharArray {
        val sets = sets(o)
        val pool = sets.joinToString("").toCharArray()
        val out = CharArray(o.length)
        while (true) {
            for (i in out.indices) out[i] = pool[random.nextInt(pool.size)]
            if (sets.all { set -> out.any { it in set } }) return out
        }
    }

    private fun words(o: GeneratorOptions): CharArray {
        val list = wordlist()
        val picked = MutableList(o.words) {
            val w = list[random.nextInt(list.size)]
            if (o.capitalize) w.replaceFirstChar { it.uppercaseChar() } else w
        }
        if (o.addDigit) {
            val at = random.nextInt(picked.size)
            picked[at] = picked[at] + ('0' + random.nextInt(10))
        }
        return picked.joinToString(o.separator.toString()).toCharArray()
    }

    companion object {
        const val LOWER = "abcdefghijklmnopqrstuvwxyz"
        const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        const val DIGITS = "0123456789"

        /** Printable ASCII symbols minus quotes, backslash, and backtick, which some forms mangle. */
        const val SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"

        fun sets(o: GeneratorOptions): List<String> = buildList {
            if (o.lower) add(LOWER)
            if (o.upper) add(UPPER)
            if (o.digits) add(DIGITS)
            if (o.symbols) add(SYMBOLS)
        }

        /**
         * Strength estimate in bits for the UI. Characters: length × log2(pool), a slight
         * overestimate because of the one-per-set rule. Words: words × log2(7 776), plus
         * log2(10 × words) for the digit.
         */
        fun entropyBits(options: GeneratorOptions, wordCount: Int = EffWordlist.SIZE): Double {
            val o = options.sanitized()
            return when (o.mode) {
                GeneratorOptions.Mode.Characters -> o.length * log2(sets(o).sumOf { it.length }.toDouble())
                GeneratorOptions.Mode.Words -> o.words * log2(wordCount.toDouble()) +
                    if (o.addDigit) log2(10.0 * o.words) else 0.0
            }
        }

        private fun log2(x: Double) = ln(x) / ln(2.0)
    }
}

/**
 * The EFF large wordlist (2016), shipped unmodified as a Java resource so its SHA-256 can be
 * checked against the published file. Lines are `<5 dice digits>\t<word>`.
 */
object EffWordlist {
    const val SIZE = 7_776
    const val RESOURCE = "/eff_large_wordlist.txt"

    /** SHA-256 of https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt */
    const val SHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"

    val words: List<String> by lazy { parse(readResource()) }

    fun readResource(): ByteArray =
        (EffWordlist::class.java.getResourceAsStream(RESOURCE) ?: throw IOException("Wordlist missing"))
            .use { it.readBytes() }

    fun parse(bytes: ByteArray): List<String> {
        val words = String(bytes, Charsets.US_ASCII).lineSequence()
            .filter { it.isNotBlank() }
            .map { line ->
                val tab = line.indexOf('\t')
                check(tab == 5) { "Bad wordlist line" }
                line.substring(tab + 1)
            }
            .toList()
        check(words.size == SIZE && words.toSet().size == SIZE) { "Bad wordlist" }
        return words
    }
}
