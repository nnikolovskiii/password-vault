package com.nnikolovskii.vault.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class PassphraseScheduleTest {
    private val t0 = 1_760_000_000_000L
    private val day = 24L * 60 * 60 * 1000

    @Test
    fun dueAfterSevenDays() {
        assertFalse(PassphraseSchedule.due(t0, t0))
        assertFalse(PassphraseSchedule.due(t0, t0 + 7 * day - 1))
        assertTrue(PassphraseSchedule.due(t0, t0 + 7 * day))
        assertTrue(PassphraseSchedule.due(t0, t0 + 365 * day))
    }

    @Test
    fun neverProvenIsDue() {
        assertTrue(PassphraseSchedule.due(null, t0))
    }

    @Test
    fun aClockMovedBackIsDueUnlessItIsSmallSkew() {
        assertFalse(PassphraseSchedule.due(t0, t0 - 60_000))
        assertFalse(PassphraseSchedule.due(t0, t0 - PassphraseSchedule.CLOCK_SKEW_MILLIS))
        assertTrue(PassphraseSchedule.due(t0, t0 - PassphraseSchedule.CLOCK_SKEW_MILLIS - 1))
        assertTrue(PassphraseSchedule.due(t0, t0 - 30 * day))
    }

    @Test
    fun codecRoundTripAndRejects() {
        assertEquals(t0, PassphraseSchedule.decode(PassphraseSchedule.encode(t0)))
        assertEquals(0L, PassphraseSchedule.decode(PassphraseSchedule.encode(0L)))
        for (bad in listOf(ByteArray(0), ByteArray(9), PassphraseSchedule.encode(t0) + 0)) {
            try {
                PassphraseSchedule.decode(bad)
                fail()
            } catch (_: CodecException) {
            }
        }
    }
}
