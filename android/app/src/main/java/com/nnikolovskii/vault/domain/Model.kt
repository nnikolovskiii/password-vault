package com.nnikolovskii.vault.domain

import com.nnikolovskii.vault.crypto.Wipe

/** Field limits from PLAN.md (code points). */
object Limits {
    const val TITLE = 200
    const val USERNAME = 500
    const val URL = 2_000
    const val PASSWORD = 1_000
    const val NOTES = 10_000
}

/**
 * Decrypted summary blob: what the list needs. Titles and usernames reveal which services he
 * uses, so [toString] redacts everything but the random id.
 */
class EntrySummary(
    val id: String,
    val title: String,
    val username: String,
    val url: String,
    val createdAt: Long,
    val updatedAt: Long,
    /** Codec tag 6. Tags say what he groups together, so they are as private as titles. */
    val tags: List<String> = emptyList(),
) {
    override fun toString(): String = "EntrySummary(id=$id, redacted)"
}

/** Summary payload as encoded in the blob (no id: the id is the row key and lives in the AAD). */
class SummaryPayload(
    val title: String,
    val username: String,
    val url: String,
    val createdAt: Long,
    val updatedAt: Long,
    val tags: List<String> = emptyList(),
) {
    override fun toString(): String = "SummaryPayload(redacted)"
}

/**
 * Decrypted secret blob. Held only while copied, revealed, or edited, then [wipe]d.
 */
class EntrySecret(
    val password: CharArray,
    val notes: CharArray,
) {
    fun wipe() = Wipe.chars(password, notes)

    override fun toString(): String = "EntrySecret(redacted)"
}

/** What Add / Edit hands to the repository. [password] and [notes] are wiped after save. */
class EntryDraft(
    val title: String,
    val username: String,
    val url: String,
    val password: CharArray,
    val notes: CharArray,
    val tags: List<String> = emptyList(),
) {
    fun wipe() = Wipe.chars(password, notes)

    override fun toString(): String = "EntryDraft(redacted)"
}

/** One list row: a decrypted summary, or a row whose blob would not open. */
sealed interface EntryRow {
    val id: String

    class Ok(val summary: EntrySummary) : EntryRow {
        override val id: String get() = summary.id
        override fun toString(): String = "EntryRow.Ok($summary)"
    }

    class Damaged(override val id: String) : EntryRow {
        override fun toString(): String = "EntryRow.Damaged(id=$id)"
    }
}

fun CharSequence.codePointLength(): Int = Character.codePointCount(this, 0, length)

fun CharArray.codePointLength(): Int = Character.codePointCount(this, 0, size)
