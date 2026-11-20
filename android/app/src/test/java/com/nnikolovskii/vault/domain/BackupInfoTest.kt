package com.nnikolovskii.vault.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class BackupInfoTest {
    private val day = 24L * 60 * 60 * 1000
    private val now = 1_760_000_000_000L

    @Test
    fun codecRoundTrip() {
        for (info in listOf(BackupInfo.NONE, BackupInfo(null, true), BackupInfo(now, false), BackupInfo(0L, true))) {
            val back = BackupInfo.decode(info.encode())
            assertEquals(info.lastBackupAt, back.lastBackupAt)
            assertEquals(info.changedSinceBackup, back.changedSinceBackup)
        }
        assertEquals(BackupInfo.SIZE, BackupInfo.NONE.encode().size)
    }

    @Test
    fun malformedPayloadIsRejected() {
        val good = BackupInfo(now, true).encode()
        for (bad in listOf(ByteArray(0), good.copyOf(9), good + 0, good.copyOf().also { it[0] = 2 }, good.copyOf().also { it[9] = 7 })) {
            try {
                BackupInfo.decode(bad)
                fail("decoded a malformed payload")
            } catch (_: CodecException) {
            }
        }
    }

    @Test
    fun toStringIsRedacted() {
        assertFalse(BackupInfo(now, true).toString().contains(now.toString()))
    }

    @Test
    fun emptyVaultNeverReminds() {
        assertFalse(BackupReminder.status(BackupInfo.NONE, 0, now).remind)
    }

    @Test
    fun neverBackedUpWithEntriesReminds() {
        val s = BackupReminder.status(BackupInfo(null, true), 1, now)
        assertTrue(s.remind)
        assertNull(s.daysSinceBackup)
        assertEquals("No backup yet", BackupReminder.label(s))
    }

    @Test
    fun remindsOnlyWhenChangedAndOlderThan30Days() {
        val changed = { age: Long -> BackupReminder.status(BackupInfo(now - age, true), 3, now) }
        val unchanged = { age: Long -> BackupReminder.status(BackupInfo(now - age, false), 3, now) }
        assertFalse(changed(30 * day - 1).remind)
        assertTrue(changed(30 * day).remind)
        assertFalse(unchanged(90 * day).remind)
        assertEquals(29, changed(30 * day - 1).daysSinceBackup)
    }

    @Test
    fun labels() {
        val at = { age: Long -> BackupReminder.label(BackupReminder.status(BackupInfo(now - age, false), 1, now)) }
        assertEquals("Last backup: today", at(day - 1))
        assertEquals("Last backup: yesterday", at(day))
        assertEquals("Last backup: 12 days ago", at(12 * day + 5))
        // Clock moved backwards: today, never negative.
        assertEquals("Last backup: today", at(-5 * day))
    }
}
