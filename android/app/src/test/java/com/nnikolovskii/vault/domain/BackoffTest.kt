package com.nnikolovskii.vault.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class BackoffTest {
    @Test
    fun fiveFreeFailuresThenDoublingFrom30sToThe15MinuteCap() {
        val expected = mapOf(
            1 to 0L, 2 to 0L, 3 to 0L, 4 to 0L,
            5 to 30_000L, 6 to 60_000L, 7 to 120_000L, 8 to 240_000L, 9 to 480_000L,
            10 to 900_000L, 11 to 900_000L, 50 to 900_000L, Int.MAX_VALUE to 900_000L,
        )
        for ((n, ms) in expected) assertEquals("after $n", ms, Backoff.delayAfter(n))
    }

    @Test
    fun failuresAccumulateAndDeadlineFollowsTheSchedule() {
        var b = Backoff()
        val now = 1_000_000L
        repeat(4) {
            b = b.onFailure(now)
            assertEquals(0L, b.remainingMillis(now))
        }
        b = b.onFailure(now)
        assertEquals(5, b.failures)
        assertEquals(30_000L, b.remainingMillis(now))
        assertEquals(10_000L, b.remainingMillis(now + 20_000))
        assertEquals(0L, b.remainingMillis(now + 30_000))
        b = b.onFailure(now + 30_000)
        assertEquals(60_000L, b.remainingMillis(now + 30_000))
    }

    @Test
    fun resetOnSuccess() {
        var b = Backoff()
        repeat(9) { b = b.onFailure(0L) }
        b = b.onSuccess()
        assertEquals(0, b.failures)
        assertEquals(0L, b.remainingMillis(0L))
        b = b.onFailure(0L)
        assertEquals(0L, b.remainingMillis(0L))
    }

    @Test
    fun clockMovedBackwardsCannotExtendBeyondTheDelay() {
        var b = Backoff()
        repeat(5) { b = b.onFailure(10_000_000L) }
        // Wall clock set back by a day: still at most the 30 s delay, not a day.
        assertEquals(30_000L, b.remainingMillis(10_000_000L - 86_400_000L))
    }
}
