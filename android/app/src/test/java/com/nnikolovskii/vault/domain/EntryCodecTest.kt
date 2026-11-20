package com.nnikolovskii.vault.domain

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class EntryCodecTest {
    private fun summary(title: String = "Bank", username: String = "", url: String = "", created: Long = 1L, updated: Long = 2L) =
        SummaryPayload(title, username, url, created, updated)

    private fun roundTripSummary(p: SummaryPayload): SummaryPayload = EntryCodec.decodeSummary(EntryCodec.encodeSummary(p))

    private fun roundTripSecret(password: String, notes: String): EntrySecret =
        EntryCodec.decodeSecret(EntryCodec.encodeSecret(EntrySecret(password.toCharArray(), notes.toCharArray())))

    private fun expectCodecError(block: () -> Unit) {
        try {
            block()
            fail("expected CodecException")
        } catch (_: CodecException) {
        }
    }

    @Test
    fun summaryRoundTripWithEmptyOptionalFields() {
        val p = roundTripSummary(summary(title = "Bank", created = 0L, updated = 0L))
        assertEquals("Bank", p.title)
        assertEquals("", p.username)
        assertEquals("", p.url)
        assertEquals(0L, p.createdAt)
        assertEquals(0L, p.updatedAt)
    }

    @Test
    fun summaryRoundTripCyrillicEmojiAndRealTimestamps() {
        val p = roundTripSummary(
            SummaryPayload("Пошта 📬", "никола@пример.мк", "https://пример.мк/вход?x=1", 1_760_000_000_000L, 1_760_000_123_456L),
        )
        assertEquals("Пошта 📬", p.title)
        assertEquals("никола@пример.мк", p.username)
        assertEquals("https://пример.мк/вход?x=1", p.url)
        assertEquals(1_760_000_000_000L, p.createdAt)
        assertEquals(1_760_000_123_456L, p.updatedAt)
    }

    @Test
    fun secretRoundTrip() {
        val s = roundTripSecret("p@ss — лозинка 🔐", "line 1\nбелешка\n\t🙂")
        assertEquals("p@ss — лозинка 🔐", String(s.password))
        assertEquals("line 1\nбелешка\n\t🙂", String(s.notes))
        val empty = roundTripSecret("", "")
        assertEquals(0, empty.password.size)
        assertEquals(0, empty.notes.size)
    }

    @Test
    fun maxLengthsInCodePointsRoundTrip() {
        val title = "🔑".repeat(Limits.TITLE) // 200 code points, 400 UTF-16 chars
        val p = roundTripSummary(summary(title = title, username = "u".repeat(Limits.USERNAME), url = "ш".repeat(Limits.URL)))
        assertEquals(title, p.title)
        assertEquals(Limits.USERNAME, p.username.length)
        assertEquals(Limits.URL, p.url.length)
        val s = roundTripSecret("ж".repeat(Limits.PASSWORD), "😀".repeat(Limits.NOTES))
        assertEquals(Limits.PASSWORD, s.password.size)
        assertEquals(Limits.NOTES, s.notes.codePointLength())
    }

    @Test
    fun overLimitsAndMissingTitleAreRejected() {
        expectCodecError { EntryCodec.encodeSummary(summary(title = "a".repeat(Limits.TITLE + 1))) }
        expectCodecError { EntryCodec.encodeSummary(summary(username = "a".repeat(Limits.USERNAME + 1))) }
        expectCodecError { EntryCodec.encodeSummary(summary(url = "a".repeat(Limits.URL + 1))) }
        expectCodecError { EntryCodec.encodeSummary(summary(title = "")) }
        expectCodecError { EntryCodec.encodeSummary(summary(title = "   ")) }
        expectCodecError { EntryCodec.encodeSecret(EntrySecret(CharArray(Limits.PASSWORD + 1) { 'x' }, CharArray(0))) }
        expectCodecError { EntryCodec.encodeSecret(EntrySecret(CharArray(0), CharArray(Limits.NOTES + 1) { 'x' })) }
    }

    @Test
    fun loneSurrogateIsRejectedNotReplaced() {
        expectCodecError { EntryCodec.encodeSecret(EntrySecret(charArrayOf('a', '\uD83D'), CharArray(0))) }
    }

    @Test
    fun unknownTagsAreSkipped() {
        val known = EntryCodec.encodeSummary(summary(title = "Mail", username = "me"))
        // Append tag 7 (unassigned), tag 99 (unknown), and tag 18 (a secret tag) with arbitrary bytes.
        val extra = byteArrayOf(7, 3, 1, 2, 3, 99, 0, 18, 2, 'x'.code.toByte(), 'y'.code.toByte())
        val p = EntryCodec.decodeSummary(known + extra)
        assertEquals("Mail", p.title)
        assertEquals("me", p.username)

        val secret = EntryCodec.encodeSecret(EntrySecret("pw".toCharArray(), CharArray(0)))
        val withTotp = secret + byteArrayOf(18, 4, 1, 2, 3, 4) + byteArrayOf(19, 0)
        val s = EntryCodec.decodeSecret(withTotp)
        assertEquals("pw", String(s.password))
    }

    @Test
    fun secretTagsInASummaryBlobAreIgnoredAndViceVersa() {
        val secretBytes = EntryCodec.encodeSecret(EntrySecret("pw".toCharArray(), "n".toCharArray()))
        expectCodecError { EntryCodec.decodeSummary(secretBytes) } // no title
        val summaryBytes = EntryCodec.encodeSummary(summary())
        val s = EntryCodec.decodeSecret(summaryBytes)
        assertEquals(0, s.password.size)
    }

    @Test
    fun malformedPayloadsAreRejected() {
        val good = EntryCodec.encodeSummary(summary(title = "Mail"))
        expectCodecError { EntryCodec.decodeSummary(ByteArray(0)) }
        expectCodecError { EntryCodec.decodeSummary(good.copyOf().also { it[0] = 2 }) }
        expectCodecError { EntryCodec.decodeSummary(good.copyOf(good.size - 1)) }
        expectCodecError { EntryCodec.decodeSummary(byteArrayOf(1, 1, 0x7F, 'a'.code.toByte())) } // length overrun
        expectCodecError { EntryCodec.decodeSummary(byteArrayOf(1, 1, 0x80.toByte())) } // truncated varint
        expectCodecError { EntryCodec.decodeSummary(byteArrayOf(1, 1, 2, 0xC3.toByte(), 0x28)) } // bad UTF-8
    }

    @Test
    fun layoutIsVersionThenTlv() {
        val bytes = EntryCodec.encodeSummary(SummaryPayload("A", "", "", 0L, 300L))
        assertArrayEquals(
            byteArrayOf(1, 1, 1, 'A'.code.toByte(), 4, 1, 0, 5, 2, 0xAC.toByte(), 0x02),
            bytes,
        )
    }
}
