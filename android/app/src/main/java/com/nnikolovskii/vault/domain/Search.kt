package com.nnikolovskii.vault.domain

import java.text.Normalizer
import java.util.Locale

/**
 * List search over decrypted summaries, in memory, while unlocked. Nothing is indexed or written:
 * a plaintext index on disk would undo the encrypted titles.
 *
 * - Case- and accent-insensitive (NFKD, combining marks dropped), so "gmail" finds "GMail" and
 *   "г" finds "ѓ".
 * - Whitespace-separated terms must all match somewhere in title, username, URL, or tags.
 * - An optional tag filter keeps only entries carrying that tag.
 * - Title-prefix matches come first; otherwise the input (alphabetical) order is kept.
 * - Damaged rows have nothing to match, so they drop out of any search or tag filter.
 */
object Search {
    private val MARKS = Regex("\\p{Mn}+")
    private val WHITESPACE = Regex("\\s+")

    fun fold(s: String): String =
        MARKS.replace(Normalizer.normalize(s, Normalizer.Form.NFKD), "").lowercase(Locale.ROOT)

    fun terms(query: String): List<String> =
        fold(query).split(WHITESPACE).filter { it.isNotEmpty() }

    fun matches(summary: EntrySummary, terms: List<String>): Boolean {
        if (terms.isEmpty()) return true
        val fields = buildList {
            add(fold(summary.title))
            add(fold(summary.username))
            add(fold(summary.url))
            summary.tags.forEach { add(fold(it)) }
        }
        return terms.all { term -> fields.any { it.contains(term) } }
    }

    fun filter(rows: List<EntryRow>, query: String, tag: String? = null): List<EntryRow> {
        val terms = terms(query)
        if (terms.isEmpty() && tag == null) return rows
        val hits = rows.filterIsInstance<EntryRow.Ok>().filter { row ->
            val s = row.summary
            (tag == null || s.tags.any { Tags.sameTag(it, tag) }) && matches(s, terms)
        }
        val first = terms.firstOrNull() ?: return hits
        val (prefix, rest) = hits.partition { fold(it.summary.title).startsWith(first) }
        return prefix + rest
    }
}
