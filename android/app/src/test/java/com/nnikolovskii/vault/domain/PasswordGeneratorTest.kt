package com.nnikolovskii.vault.domain

import java.security.MessageDigest
import java.util.Random
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordGeneratorTest {
    private val seeded = PasswordGenerator(random = Random(42))

    private fun chars(o: GeneratorOptions) = String(seeded.generate(o))

    @Test
    fun wordlistIsTheUnmodifiedEffLargeList() {
        val bytes = EffWordlist.readResource()
        val hex = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals(EffWordlist.SHA256, hex)
        val words = EffWordlist.words
        assertEquals(7_776, words.size)
        assertEquals(7_776, words.toSet().size)
        assertEquals("abacus", words.first())
        assertEquals("zoom", words.last())
        assertTrue(words.all { w -> w.isNotEmpty() && w.all { it in 'a'..'z' || it == '-' } })
    }

    @Test
    fun charactersHaveTheLengthAndOneOfEverySet() {
        repeat(500) {
            val p = chars(GeneratorOptions(length = 8))
            assertEquals(8, p.length)
            assertTrue(p.any { it in PasswordGenerator.LOWER })
            assertTrue(p.any { it in PasswordGenerator.UPPER })
            assertTrue(p.any { it in PasswordGenerator.DIGITS })
            assertTrue(p.any { it in PasswordGenerator.SYMBOLS })
        }
    }

    @Test
    fun onlyChosenSetsAppear() {
        repeat(200) {
            val p = chars(GeneratorOptions(length = 30, upper = false, symbols = false))
            assertTrue(p.all { it in PasswordGenerator.LOWER || it in PasswordGenerator.DIGITS })
            assertTrue(p.any { it in PasswordGenerator.DIGITS })
        }
        val digits = chars(GeneratorOptions(length = 12, lower = false, upper = false, symbols = false))
        assertTrue(digits.all { it.isDigit() })
    }

    @Test
    fun symbolSetAvoidsQuotesBackslashAndBacktick() {
        for (c in "'\"\\` ") assertTrue(c !in PasswordGenerator.SYMBOLS)
    }

    @Test
    fun everyPoolCharacterTurnsUpAndNoneDominates() {
        val counts = HashMap<Char, Int>()
        val n = 2_000
        repeat(n) { chars(GeneratorOptions(length = 40)).forEach { c -> counts[c] = (counts[c] ?: 0) + 1 } }
        val pool = PasswordGenerator.sets(GeneratorOptions()).joinToString("")
        assertEquals(pool.toSet(), counts.keys)
        val expected = n * 40.0 / pool.length
        // Loose bounds: a uniform pick lands within ±25 % of the mean for every character.
        assertTrue(counts.values.all { it > expected * 0.75 && it < expected * 1.25 })
    }

    @Test
    fun wordsModeUsesListWordsAndTheSeparator() {
        val list = EffWordlist.words.toSet()
        repeat(100) {
            val p = chars(GeneratorOptions(mode = GeneratorOptions.Mode.Words, words = 6, separator = '.'))
            val parts = p.split('.')
            assertEquals(6, parts.size)
            assertTrue(parts.all { it in list })
        }
    }

    @Test
    fun capitalizeAndDigit() {
        repeat(100) {
            val p = chars(
                GeneratorOptions(mode = GeneratorOptions.Mode.Words, words = 5, separator = ' ', capitalize = true, addDigit = true),
            )
            val parts = p.split(' ')
            assertEquals(5, parts.size)
            assertTrue(parts.all { it[0].isUpperCase() })
            assertEquals(1, p.count { it.isDigit() })
            assertTrue(parts.single { w -> w.any { it.isDigit() } }.last().isDigit())
        }
    }

    @Test
    fun outOfRangeOptionsAreClamped() {
        assertEquals(GeneratorOptions.MIN_LENGTH, chars(GeneratorOptions(length = 1)).length)
        assertEquals(GeneratorOptions.MAX_LENGTH, chars(GeneratorOptions(length = 10_000)).length)
        // '.' because a few EFF words contain '-' (t-shirt, yo-yo, …).
        val few = chars(GeneratorOptions(mode = GeneratorOptions.Mode.Words, words = 1, separator = '.'))
        assertEquals(GeneratorOptions.MIN_WORDS, few.split('.').size)
        // No set chosen means every set.
        val none = GeneratorOptions(lower = false, upper = false, digits = false, symbols = false).sanitized()
        assertTrue(none.lower && none.upper && none.digits && none.symbols)
        assertEquals('-', GeneratorOptions(separator = '\n').sanitized().separator)
    }

    @Test
    fun entropyEstimates() {
        assertEquals(20 * Math.log(90.0) / Math.log(2.0), PasswordGenerator.entropyBits(GeneratorOptions()), 1e-9)
        val six = PasswordGenerator.entropyBits(GeneratorOptions(mode = GeneratorOptions.Mode.Words, words = 6))
        assertEquals(77.5, six, 0.1)
        val withDigit = PasswordGenerator.entropyBits(GeneratorOptions(mode = GeneratorOptions.Mode.Words, words = 6, addDigit = true))
        assertEquals(six + Math.log(60.0) / Math.log(2.0), withDigit, 1e-9)
    }

    @Test
    fun defaultGeneratorUsesSecureRandom() {
        val a = String(PasswordGenerator().generate(GeneratorOptions()))
        val b = String(PasswordGenerator().generate(GeneratorOptions()))
        assertTrue(a != b)
    }
}
