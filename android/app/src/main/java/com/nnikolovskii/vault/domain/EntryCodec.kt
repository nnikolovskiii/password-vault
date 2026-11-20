package com.nnikolovskii.vault.domain

import com.nnikolovskii.vault.crypto.Wipe
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** A payload did not decode, or a draft broke a field limit. Never carries field contents. */
class CodecException(message: String) : Exception(message)

/**
 * Plaintext payload codec: a version byte, then tag-length-value fields (1-byte tag, varint
 * length, value). Strings are UTF-8, timestamps are varints. Unknown tags are skipped on decode,
 * so later parts can add fields without a schema migration. Tag ids are reserved in PLAN.md.
 *
 * Secret fields go CharArray → bytes without a String, and every intermediate buffer is wiped.
 */
object EntryCodec {
    const val VERSION: Byte = 0x01

    const val TAG_TITLE = 1
    const val TAG_USERNAME = 2
    const val TAG_URL = 3
    const val TAG_CREATED_AT = 4
    const val TAG_UPDATED_AT = 5

    /** Repeated: one field per entry tag, in order (Part 3). */
    const val TAG_TAGS = 6
    const val TAG_PASSWORD = 16
    const val TAG_NOTES = 17

    fun encodeSummary(payload: SummaryPayload): ByteArray {
        if (payload.title.isBlank()) throw CodecException("Title is required")
        checkLimit(payload.title.codePointLength(), Limits.TITLE, "Title")
        checkLimit(payload.username.codePointLength(), Limits.USERNAME, "Username")
        checkLimit(payload.url.codePointLength(), Limits.URL, "URL")
        Tags.validate(payload.tags)
        val fields = ArrayList<Pair<Int, ByteArray>>(5 + payload.tags.size)
        fields += TAG_TITLE to payload.title.toByteArray(Charsets.UTF_8)
        if (payload.username.isNotEmpty()) fields += TAG_USERNAME to payload.username.toByteArray(Charsets.UTF_8)
        if (payload.url.isNotEmpty()) fields += TAG_URL to payload.url.toByteArray(Charsets.UTF_8)
        fields += TAG_CREATED_AT to varint(payload.createdAt)
        fields += TAG_UPDATED_AT to varint(payload.updatedAt)
        for (tag in payload.tags) fields += TAG_TAGS to tag.toByteArray(Charsets.UTF_8)
        return assemble(fields)
    }

    fun decodeSummary(bytes: ByteArray): SummaryPayload {
        var title: String? = null
        var username = ""
        var url = ""
        var createdAt = 0L
        var updatedAt = 0L
        val tags = ArrayList<String>()
        forEachField(bytes) { tag, start, length ->
            when (tag) {
                TAG_TITLE -> title = utf8String(bytes, start, length)
                TAG_USERNAME -> username = utf8String(bytes, start, length)
                TAG_URL -> url = utf8String(bytes, start, length)
                TAG_CREATED_AT -> createdAt = readVarintValue(bytes, start, length)
                TAG_UPDATED_AT -> updatedAt = readVarintValue(bytes, start, length)
                TAG_TAGS -> tags += utf8String(bytes, start, length)
                else -> Unit // Unknown or later-part tag: skip.
            }
        }
        return SummaryPayload(
            title = title ?: throw CodecException("Missing title"),
            username = username,
            url = url,
            createdAt = createdAt,
            updatedAt = updatedAt,
            tags = tags,
        )
    }

    fun encodeSecret(secret: EntrySecret): ByteArray {
        checkLimit(secret.password.codePointLength(), Limits.PASSWORD, "Password")
        checkLimit(secret.notes.codePointLength(), Limits.NOTES, "Notes")
        val fields = ArrayList<Pair<Int, ByteArray>>(2)
        try {
            if (secret.password.isNotEmpty()) fields += TAG_PASSWORD to utf8Bytes(secret.password)
            if (secret.notes.isNotEmpty()) fields += TAG_NOTES to utf8Bytes(secret.notes)
            return assemble(fields)
        } finally {
            fields.forEach { Wipe.bytes(it.second) }
        }
    }

    fun decodeSecret(bytes: ByteArray): EntrySecret {
        var password = CharArray(0)
        var notes = CharArray(0)
        try {
            forEachField(bytes) { tag, start, length ->
                when (tag) {
                    TAG_PASSWORD -> {
                        Wipe.chars(password)
                        password = utf8Chars(bytes, start, length)
                    }
                    TAG_NOTES -> {
                        Wipe.chars(notes)
                        notes = utf8Chars(bytes, start, length)
                    }
                    else -> Unit
                }
            }
        } catch (e: Exception) {
            Wipe.chars(password, notes)
            throw e
        }
        return EntrySecret(password, notes)
    }

    // --- TLV ---------------------------------------------------------------------------------

    /** One allocation for the whole payload, so no half-grown buffer copies are left behind. */
    internal fun assemble(fields: List<Pair<Int, ByteArray>>): ByteArray {
        var size = 1
        for ((_, value) in fields) size += 1 + varintSize(value.size.toLong()) + value.size
        val out = ByteArray(size)
        out[0] = VERSION
        var pos = 1
        for ((tag, value) in fields) {
            out[pos++] = tag.toByte()
            pos = writeVarint(value.size.toLong(), out, pos)
            value.copyInto(out, pos)
            pos += value.size
        }
        return out
    }

    internal inline fun forEachField(bytes: ByteArray, onField: (tag: Int, start: Int, length: Int) -> Unit) {
        if (bytes.isEmpty() || bytes[0] != VERSION) throw CodecException("Unknown payload version")
        var pos = 1
        while (pos < bytes.size) {
            val tag = bytes[pos++].toInt() and 0xFF
            val (lengthLong, next) = readVarint(bytes, pos)
            if (lengthLong > bytes.size - next) throw CodecException("Field overruns payload")
            val length = lengthLong.toInt()
            onField(tag, next, length)
            pos = next + length
        }
    }

    private fun checkLimit(actual: Int, max: Int, name: String) {
        if (actual > max) throw CodecException("$name is longer than $max characters")
    }

    // --- varint (unsigned LEB128) ------------------------------------------------------------

    internal fun varint(value: Long): ByteArray {
        val out = ByteArray(varintSize(value))
        writeVarint(value, out, 0)
        return out
    }

    private fun varintSize(value: Long): Int {
        require(value >= 0) { "varint must be non-negative" }
        var v = value
        var n = 1
        while (v >= 0x80) {
            v = v ushr 7
            n++
        }
        return n
    }

    private fun writeVarint(value: Long, out: ByteArray, start: Int): Int {
        var v = value
        var pos = start
        while (v >= 0x80) {
            out[pos++] = ((v and 0x7F) or 0x80).toByte()
            v = v ushr 7
        }
        out[pos++] = v.toByte()
        return pos
    }

    /** @return value and the position after it. */
    internal fun readVarint(bytes: ByteArray, start: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var pos = start
        while (true) {
            if (pos >= bytes.size) throw CodecException("Truncated varint")
            if (shift > 56) throw CodecException("Varint too long")
            val b = bytes[pos++].toInt() and 0xFF
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        if (result < 0) throw CodecException("Varint out of range")
        return result to pos
    }

    internal fun readVarintValue(bytes: ByteArray, start: Int, length: Int): Long {
        val (value, end) = readVarint(bytes, start)
        if (end != start + length) throw CodecException("Bad varint field length")
        return value
    }

    // --- UTF-8 -------------------------------------------------------------------------------

    internal fun utf8String(bytes: ByteArray, start: Int, length: Int): String {
        val chars = utf8Chars(bytes, start, length)
        return try {
            String(chars)
        } finally {
            Wipe.chars(chars)
        }
    }

    private fun utf8Chars(bytes: ByteArray, start: Int, length: Int): CharArray {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val buffer = try {
            decoder.decode(ByteBuffer.wrap(bytes, start, length))
        } catch (e: CharacterCodingException) {
            throw CodecException("Invalid UTF-8")
        }
        val out = CharArray(buffer.remaining())
        buffer.get(out)
        if (buffer.hasArray()) Wipe.chars(buffer.array())
        return out
    }

    /** CharArray → UTF-8 without a String. Lone surrogates are rejected, not replaced. */
    internal fun utf8Bytes(chars: CharArray): ByteArray {
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val buffer = try {
            encoder.encode(CharBuffer.wrap(chars))
        } catch (e: CharacterCodingException) {
            throw CodecException("Invalid characters")
        }
        val out = ByteArray(buffer.remaining())
        buffer.get(out)
        if (buffer.hasArray()) Wipe.bytes(buffer.array())
        return out
    }
}
