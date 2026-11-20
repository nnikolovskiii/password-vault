package com.nnikolovskii.vault.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SearchTest {
    private fun s(id: String, title: String, username: String = "", url: String = "", tags: List<String> = emptyList()) =
        EntryRow.Ok(EntrySummary(id, title, username, url, 0L, 0L, tags))

    private val rows: List<EntryRow> = listOf(
        s("1", "Bank of Macedonia", "nikola", "https://bank.example", listOf("money")),
        s("2", "GMail", "nikola@example.com", "https://mail.google.com", listOf("Mail", "google")),
        s("3", "Пошта", "никола", "https://пошта.мк", listOf("mail")),
        s("4", "Ѓорѓи's router", "admin", "http://192.168.1.1", listOf("home")),
        EntryRow.Damaged("5"),
        s("6", "Workday", "n.nikolovski", "https://work.example", listOf("work")),
    )

    private fun ids(query: String, tag: String? = null) = Search.filter(rows, query, tag).map { it.id }

    @Test
    fun emptyQueryReturnsEverythingInOrder() {
        assertEquals(rows, Search.filter(rows, ""))
        assertEquals(rows, Search.filter(rows, "   "))
    }

    @Test
    fun caseInsensitiveAcrossTitleUsernameUrlAndTags() {
        assertEquals(listOf("2"), ids("gmail"))
        assertEquals(listOf("2"), ids("GOOGLE.COM"))
        assertEquals(listOf("1"), ids("MONEY"))
        assertEquals(listOf("6"), ids("n.nik"))
        assertEquals(listOf("4"), ids("192.168"))
    }

    @Test
    fun cyrillicAndAccentsFold() {
        assertEquals(listOf("3"), ids("пошта"))
        assertEquals(listOf("3"), ids("ПОШТА"))
        // ѓ folds to г, so a phone keyboard without ѓ still finds it.
        assertEquals(listOf("4"), ids("горги"))
        assertEquals(listOf("4"), ids("ѓорѓи"))
    }

    @Test
    fun everyTermMustMatchSomewhere() {
        assertEquals(listOf("2"), ids("gmail nikola"))
        assertEquals(emptyList<String>(), ids("gmail work"))
        assertEquals(listOf("1"), ids("bank money"))
    }

    @Test
    fun titlePrefixMatchesComeFirst() {
        // "mail" hits GMail (tag Mail / url) and Пошта (tag mail); neither title starts with it.
        assertEquals(listOf("2", "3"), ids("mail"))
        // "work" is a prefix of Workday's title; it comes before any other match.
        assertEquals("6", ids("work").first())
        val extra = rows + s("7", "Alpha", "", "https://workplace.example")
        assertEquals(listOf("6", "7"), Search.filter(extra, "work").map { it.id })
    }

    @Test
    fun tagFilterIsCaseInsensitiveAndCombinesWithTheQuery() {
        assertEquals(listOf("2", "3"), ids("", tag = "MAIL"))
        assertEquals(listOf("3"), ids("пошта", tag = "mail"))
        assertEquals(emptyList<String>(), ids("bank", tag = "mail"))
    }

    @Test
    fun damagedRowsDropOutOfAnyFilter() {
        assertTrue(Search.filter(rows, "").any { it is EntryRow.Damaged })
        assertFalse(Search.filter(rows, "a").any { it is EntryRow.Damaged })
        assertFalse(Search.filter(rows, "", tag = "home").any { it is EntryRow.Damaged })
    }

    @Test
    fun matchesWithNoTermsIsTrue() {
        assertTrue(Search.matches((rows[0] as EntryRow.Ok).summary, emptyList()))
    }
}
