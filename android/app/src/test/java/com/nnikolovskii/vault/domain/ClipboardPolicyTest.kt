package com.nnikolovskii.vault.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ClipboardPolicyTest {
    @Test
    fun foregroundClearsOnlyOurClip() {
        assertTrue(ClipboardPolicy.shouldClear(pendingCopy = true, inForeground = true, clipIsOurs = true))
        assertFalse(ClipboardPolicy.shouldClear(pendingCopy = true, inForeground = true, clipIsOurs = false))
    }

    @Test
    fun foregroundUnreadableClipIsTreatedAsOurs() {
        assertTrue(ClipboardPolicy.shouldClear(pendingCopy = true, inForeground = true, clipIsOurs = null))
    }

    @Test
    fun backgroundClearsUnconditionally() {
        assertTrue(ClipboardPolicy.shouldClear(pendingCopy = true, inForeground = false, clipIsOurs = null))
        assertTrue(ClipboardPolicy.shouldClear(pendingCopy = true, inForeground = false, clipIsOurs = false))
    }

    @Test
    fun lockWithNothingCopiedLeavesTheClipboardAlone() {
        // Lock runs the same decision; with no pending vault copy it never touches the clipboard.
        assertFalse(ClipboardPolicy.shouldClear(pendingCopy = false, inForeground = true, clipIsOurs = null))
        assertFalse(ClipboardPolicy.shouldClear(pendingCopy = false, inForeground = false, clipIsOurs = null))
    }

    @Test
    fun clearsAfter30Seconds() {
        assertEquals(30_000L, ClipboardPolicy.CLEAR_AFTER_MILLIS)
    }
}
