package com.nnikolovskii.vault.domain

/**
 * Whether to clear the clipboard (30 s after a copy, and on lock).
 *
 * - Nothing of ours was copied since the last clear: leave the clipboard alone.
 * - Foreground: clear only if the current clip still carries the vault's marker. If the clip
 *   cannot be read (no input focus), treat it as ours.
 * - Background: Android 10+ will not let us read the clipboard, so clear unconditionally. That
 *   can wipe something copied in the last 30 s; the safe default is worth that.
 */
object ClipboardPolicy {
    const val CLEAR_AFTER_MILLIS = 30_000L

    fun shouldClear(pendingCopy: Boolean, inForeground: Boolean, clipIsOurs: Boolean?): Boolean =
        when {
            !pendingCopy -> false
            !inForeground -> true
            else -> clipIsOurs ?: true
        }
}
