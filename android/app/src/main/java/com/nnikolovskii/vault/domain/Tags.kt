package com.nnikolovskii.vault.domain

import java.text.Collator
import java.text.Normalizer
import java.util.Locale

/**
 * Entry tags (codec tag 6, inside the summary blob, never a column). Typed as one comma-separated
 * field; each tag is NFC, trimmed, with inner whitespace collapsed. Duplicates are dropped
 * case-insensitively, keeping the first spelling.
 */
object Tags {
    const val MAX_TAGS = 20
    const val MAX_LENGTH = 40
    const val SEPARATOR = ','

    private val WHITESPACE = Regex("\\s+")

    fun normalize(tag: String): String =
        Normalizer.normalize(tag, Normalizer.Form.NFC).replace(WHITESPACE, " ").trim()

    /** "Bank, work ,  bank" → ["Bank", "work"]. Limits are checked by [validate], not here. */
    fun parse(input: String): List<String> = dedupe(input.split(SEPARATOR).map(::normalize))

    /** For the Edit field. */
    fun format(tags: List<String>): String = tags.joinToString("$SEPARATOR ")

    /** @throws CodecException with a message that never contains the tag itself. */
    fun validate(tags: List<String>) {
        if (tags.size > MAX_TAGS) throw CodecException("At most $MAX_TAGS tags")
        val seen = HashSet<String>()
        for (t in tags) {
            if (t.isEmpty() || t != normalize(t)) throw CodecException("Bad tag")
            if (t.codePointLength() > MAX_LENGTH) throw CodecException("A tag is longer than $MAX_LENGTH characters")
            if (t.any { it == SEPARATOR || Character.isISOControl(it) }) throw CodecException("Bad tag")
            if (!seen.add(key(t))) throw CodecException("Duplicate tag")
        }
    }

    /** Every tag in use, once (case-insensitive), sorted with the locale collator. */
    fun inUse(summaries: List<EntrySummary>): List<String> {
        val collator = Collator.getInstance().apply { strength = Collator.SECONDARY }
        return dedupe(summaries.flatMap { it.tags }).sortedWith { a, b -> collator.compare(a, b) }
    }

    fun sameTag(a: String, b: String): Boolean = key(a) == key(b)

    private fun dedupe(tags: List<String>): List<String> {
        val seen = HashSet<String>()
        return tags.filter { it.isNotEmpty() && seen.add(key(it)) }
    }

    private fun key(tag: String): String = tag.lowercase(Locale.ROOT)
}
