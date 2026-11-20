package com.nnikolovskii.vault.session

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import com.nnikolovskii.vault.domain.ClipboardPolicy
import com.nnikolovskii.vault.domain.toHex
import java.security.SecureRandom

/**
 * Every copy from the vault: flagged sensitive (masked preview on Android 13+, kept out of
 * Gboard's history), tagged with a random marker, and cleared after the configured delay (30 s by
 * default) and on lock per [ClipboardPolicy]. Main thread only.
 */
class ClipboardGuard(
    context: Context,
    private val isForeground: () -> Boolean,
    private val clearAfterMillis: () -> Long = { ClipboardPolicy.CLEAR_AFTER_MILLIS },
) {
    private val clipboard = context.getSystemService(ClipboardManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private val random = SecureRandom()
    private val clearTask = Runnable { clearIfOurs() }

    /** Marker of the clip we last put on the clipboard and have not cleared yet. */
    private var pendingMarker: String? = null

    /** Copies [text] (password, username, URL). The caller wipes its own CharArray. */
    fun copy(label: String, text: CharArray) {
        val marker = ByteArray(16).also(random::nextBytes).toHex()
        // ClipData needs a CharSequence that survives parceling; the clipboard keeps it anyway.
        val clip = ClipData.newPlainText(label, String(text))
        clip.description.extras = PersistableBundle().apply {
            putBoolean(EXTRA_IS_SENSITIVE, true)
            putString(EXTRA_MARKER, marker)
        }
        clipboard.setPrimaryClip(clip)
        pendingMarker = marker
        handler.removeCallbacks(clearTask)
        handler.postDelayed(clearTask, clearAfterMillis())
    }

    /** Called on every lock. */
    fun onLock() {
        clearIfOurs()
    }

    private fun clearIfOurs() {
        handler.removeCallbacks(clearTask)
        val marker = pendingMarker
        val foreground = isForeground()
        val ours: Boolean? = if (marker != null && foreground) currentClipIsOurs(marker) else null
        if (ClipboardPolicy.shouldClear(marker != null, foreground, ours)) {
            try {
                clipboard.clearPrimaryClip()
            } catch (_: SecurityException) {
                // Nothing else to try.
            }
        }
        pendingMarker = null
    }

    /** null when Android will not tell us (no input focus): the policy treats that as ours. */
    private fun currentClipIsOurs(marker: String): Boolean? =
        try {
            val description = clipboard.primaryClipDescription
            when {
                description != null -> description.extras?.getString(EXTRA_MARKER) == marker
                clipboard.hasPrimaryClip() -> null
                else -> null
            }
        } catch (_: SecurityException) {
            null
        }

    private companion object {
        /** ClipDescription.EXTRA_IS_SENSITIVE (API 33); older Gboard builds read the same key. */
        const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
        const val EXTRA_MARKER = "com.nnikolovskii.vault.clip"
    }
}
