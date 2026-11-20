package com.nnikolovskii.vault.domain

import com.nnikolovskii.vault.domain.AutoLockPolicy.Reason
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AutoLockPolicyTest {
    private val t0 = 5_000_000L

    private fun unlocked() = AutoLockPolicy().also { it.onUnlocked(t0, inForeground = true) }

    @Test
    fun background59sStaysOpen60sLocks() {
        val p = unlocked()
        p.onBackground(t0)
        assertNull(p.check(t0 + 59_000))
        assertEquals(Reason.Background, p.check(t0 + 60_000))
    }

    @Test
    fun onStartAfter59sStaysOpenAfter60sLocks() {
        val a = unlocked()
        a.onBackground(t0)
        assertNull(a.onForeground(t0 + 59_999))

        val b = unlocked()
        b.onBackground(t0)
        assertEquals(Reason.Background, b.onForeground(t0 + 60_000))
    }

    @Test
    fun onStartAfterALongFreezeLocks() {
        // The timer never ran (frozen cached process); ON_START sees hours of elapsed realtime.
        val p = unlocked()
        p.onBackground(t0)
        assertEquals(Reason.Background, p.onForeground(t0 + 6 * 3_600_000L))
    }

    @Test
    fun idleFiveMinutesInForegroundLocks() {
        val p = unlocked()
        assertNull(p.check(t0 + 299_999))
        assertEquals(Reason.Idle, p.check(t0 + 300_000))
    }

    @Test
    fun interactionResetsIdle() {
        val p = unlocked()
        p.onInteraction(t0 + 200_000)
        assertNull(p.check(t0 + 300_000))
        assertNull(p.check(t0 + 499_999))
        assertEquals(Reason.Idle, p.check(t0 + 500_000))
        assertEquals(t0 + 500_000, p.nextDeadline())
    }

    @Test
    fun returningInTimeCountsAsInteraction() {
        val p = unlocked()
        p.onInteraction(t0 + 250_000)
        p.onBackground(t0 + 250_000)
        assertNull(p.onForeground(t0 + 290_000))
        // Idle restarts from the return, not from the last touch before leaving.
        assertNull(p.check(t0 + 300_000))
        assertEquals(Reason.Idle, p.check(t0 + 590_000))
    }

    @Test
    fun backgroundDeadlineIsWhatTheTimerWaitsFor() {
        val p = unlocked()
        p.onBackground(t0 + 10)
        assertEquals(t0 + 10 + 60_000, p.nextDeadline())
        // A second ON_STOP does not push the deadline out.
        p.onBackground(t0 + 30_000)
        assertEquals(t0 + 10 + 60_000, p.nextDeadline())
    }

    @Test
    fun screenOffLocksImmediately() {
        assertEquals(Reason.ScreenOff, unlocked().onScreenOff())
    }

    @Test
    fun unlockFinishingInBackgroundStartsTheBackgroundClock() {
        val p = AutoLockPolicy()
        p.onUnlocked(t0, inForeground = false)
        assertEquals(Reason.Background, p.check(t0 + 60_000))
    }

    @Test
    fun customTimeoutsFromSettings() {
        val p = AutoLockPolicy(backgroundMillis = 15_000, idleMillis = 60_000)
        p.onUnlocked(t0, inForeground = true)
        assertNull(p.check(t0 + 59_999))
        assertEquals(Reason.Idle, p.check(t0 + 60_000))
        p.onBackground(t0 + 1_000)
        assertNull(p.onForeground(t0 + 15_999))
        p.onBackground(t0 + 20_000)
        assertEquals(Reason.Background, p.onForeground(t0 + 35_000))
    }

    @Test
    fun changingTimeoutsAppliesToTheRunningCountdown() {
        val p = unlocked()
        p.onBackground(t0)
        assertNull(p.check(t0 + 20_000))
        // He shortens the background lock to 15 s while the vault sits in the background.
        p.setTimeouts(15_000, 300_000)
        assertEquals(Reason.Background, p.check(t0 + 20_000))
        assertEquals(t0 + 15_000, p.nextDeadline())
    }

    @Test(expected = IllegalArgumentException::class)
    fun zeroTimeoutIsRefused() {
        unlocked().setTimeouts(0, 300_000)
    }
}
