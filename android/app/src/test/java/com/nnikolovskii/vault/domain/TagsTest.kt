package com.nnikolovskii.vault.domain

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class TagsTest {
    private fun expectCodecError(block: () -> Unit) {
        try {
            block()
            fail("expected CodecException")
        } catch (_: CodecException) {
        }
    }

    private fun summary(tags: List<String>) = SummaryPayload("Bank", "", "", 1L, 2L, tags)

    @Test
    fun parseTrimsCollapsesAndDedupesCaseInsensitively() {
        assertEquals(listOf("Bank", "work stuff", "ПОШТА"), Tags.parse(" Bank , work   stuff,,bank, ПОШТА ,Пошта, "))
        assertEquals(emptyList<String>(), Tags.parse(""))
        assertEquals(emptyList<String>(), Tags.parse(" , ,"))
    }

    @Test
    fun parseNormalizesToNfc() {
        // ѓ typed as г + combining acute becomes the precomposed letter.
        assertEquals(listOf("ѓ"), Tags.parse("ѓ"))
        assertTrue(Tags.sameTag("ѓ", Tags.parse("ѓ").single()))
    }

    @Test
    fun formatRoundTripsThroughParse() {
        val tags = listOf("Bank", "work stuff", "🔐")
        assertEquals(tags, Tags.parse(Tags.format(tags)))
    }

    @Test
    fun validateEnforcesLimits() {
        Tags.validate(List(Tags.MAX_TAGS) { "t$it" })
        expectCodecError { Tags.validate(List(Tags.MAX_TAGS + 1) { "t$it" }) }
        Tags.validate(listOf("🔑".repeat(Tags.MAX_LENGTH)))
        expectCodecError { Tags.validate(listOf("a".repeat(Tags.MAX_LENGTH + 1))) }
        expectCodecError { Tags.validate(listOf("")) }
        expectCodecError { Tags.validate(listOf(" padded ")) }
        expectCodecError { Tags.validate(listOf("a,b")) }
        expectCodecError { Tags.validate(listOf("tab\there")) }
        expectCodecError { Tags.validate(listOf("Bank", "bank")) }
    }

    @Test
    fun validationMessagesNeverContainTheTag() {
        try {
            Tags.validate(listOf("SecretTagName".repeat(4)))
            fail()
        } catch (e: CodecException) {
            assertFalse(e.message!!.contains("SecretTagName"))
        }
    }

    @Test
    fun codecTag6RoundTripsInOrder() {
        val tags = listOf("Bank", "Пошта", "🔐 keys", "work")
        val p = EntryCodec.decodeSummary(EntryCodec.encodeSummary(summary(tags)))
        assertEquals(tags, p.tags)
        assertEquals("Bank", p.title)
    }

    @Test
    fun codecWritesOneTag6FieldPerTagAfterTheTimestamps() {
        val bytes = EntryCodec.encodeSummary(SummaryPayload("A", "", "", 0L, 300L, listOf("x", "yz")))
        assertArrayEquals(
            byteArrayOf(
                1, 1, 1, 'A'.code.toByte(), 4, 1, 0, 5, 2, 0xAC.toByte(), 0x02,
                6, 1, 'x'.code.toByte(), 6, 2, 'y'.code.toByte(), 'z'.code.toByte(),
            ),
            bytes,
        )
    }

    @Test
    fun aPart1SummaryWithoutTagsDecodesToNoTags() {
        // Exactly what 0.1.0 / 0.2.0 wrote: no tag 6 fields.
        val old = byteArrayOf(1, 1, 1, 'A'.code.toByte(), 4, 1, 0, 5, 2, 0xAC.toByte(), 0x02)
        assertEquals(emptyList<String>(), EntryCodec.decodeSummary(old).tags)
    }

    @Test
    fun codecRejectsInvalidTagLists() {
        expectCodecError { EntryCodec.encodeSummary(summary(List(Tags.MAX_TAGS + 1) { "t$it" })) }
        expectCodecError { EntryCodec.encodeSummary(summary(listOf("a".repeat(Tags.MAX_LENGTH + 1)))) }
        expectCodecError { EntryCodec.encodeSummary(summary(listOf("Bank", "BANK"))) }
    }

    @Test
    fun badUtf8InATagIsRejected() {
        val bytes = EntryCodec.encodeSummary(summary(emptyList())) + byteArrayOf(6, 2, 0xC3.toByte(), 0x28)
        expectCodecError { EntryCodec.decodeSummary(bytes) }
    }

    @Test
    fun inUseIsDedupedAndSorted() {
        val a = EntrySummary("1", "A", "", "", 0, 0, listOf("work", "Bank"))
        val b = EntrySummary("2", "B", "", "", 0, 0, listOf("bank", "alpha"))
        assertEquals(listOf("alpha", "Bank", "work"), Tags.inUse(listOf(a, b)))
    }
}
