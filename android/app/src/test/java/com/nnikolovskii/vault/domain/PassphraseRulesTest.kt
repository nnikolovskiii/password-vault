package com.nnikolovskii.vault.domain

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PassphraseRulesTest {
    @Test
    fun elevenVersusTwelveCodePoints() {
        assertFalse(PassphraseRules.check("a".repeat(11), "a".repeat(11), true).longEnough)
        assertTrue(PassphraseRules.check("a".repeat(12), "a".repeat(12), true).ok)
        // Emoji are one code point each (two UTF-16 chars).
        assertFalse(PassphraseRules.check("🔑".repeat(11), "🔑".repeat(11), true).longEnough)
        assertTrue(PassphraseRules.check("🔑".repeat(12), "🔑".repeat(12), true).longEnough)
        // Counted after NFC: 6 × (г + combining acute) = 12 chars but 6 code points.
        assertEquals(6, PassphraseRules.codePoints("ѓ".repeat(6)))
        assertFalse(PassphraseRules.check("ѓ".repeat(6), "ѓ".repeat(6), true).longEnough)
    }

    @Test
    fun mismatchFails() {
        val c = PassphraseRules.check("correct horse battery", "correct horse batterY", true)
        assertTrue(c.longEnough)
        assertFalse(c.matches)
        assertFalse(c.ok)
        assertFalse(PassphraseRules.check("", "", true).matches)
    }

    @Test
    fun checkboxIsRequired() {
        val c = PassphraseRules.check("correct horse battery", "correct horse battery", false)
        assertTrue(c.longEnough && c.matches)
        assertFalse(c.ok)
    }

    @Test
    fun encodingIsNfcUtf8WithoutTrimming() {
        assertArrayEquals(
            PassphraseRules.encode("ѓ"),
            PassphraseRules.encode("ѓ"),
        )
        assertArrayEquals(byteArrayOf(0xD1.toByte(), 0x93.toByte()), PassphraseRules.encode("ѓ"))
        assertArrayEquals(" a ".toByteArray(), PassphraseRules.encode(" a "))
        // Decomposed and precomposed confirm the same passphrase.
        assertTrue(PassphraseRules.check("ѓ".repeat(12), "ѓ".repeat(12), true).matches)
    }
}
