package com.nnikolovskii.vault.domain

/**
 * When to lock an unlocked vault. Pure: all times come from the caller (SystemClock
 * .elapsedRealtime on the phone, which keeps counting through deep sleep).
 *
 * - Screen off: lock immediately.
 * - Background: lock once [backgroundMillis] have passed since ON_STOP. Checked again on
 *   ON_START, because a frozen cached process may never run the pending timer.
 * - Foreground idle: lock once [idleMillis] have passed since the last interaction.
 *
 * The two timeouts are user settings since Part 3 (defaults: the Part 1 constants). A change
 * applies to the running countdowns at once: they are measured from the same start times.
 */
class AutoLockPolicy(
    backgroundMillis: Long = BACKGROUND_MILLIS,
    idleMillis: Long = IDLE_MILLIS,
) {
    var backgroundMillis: Long = backgroundMillis
        private set
    var idleMillis: Long = idleMillis
        private set

    fun setTimeouts(backgroundMillis: Long, idleMillis: Long) {
        require(backgroundMillis > 0 && idleMillis > 0)
        this.backgroundMillis = backgroundMillis
        this.idleMillis = idleMillis
    }

    enum class Reason { ScreenOff, Background, Idle }

    private var backgroundedAt: Long? = null
    private var lastInteractionAt: Long = 0L

    val inBackground: Boolean get() = backgroundedAt != null

    fun onUnlocked(now: Long, inForeground: Boolean) {
        lastInteractionAt = now
        backgroundedAt = if (inForeground) null else now
    }

    fun onInteraction(now: Long) {
        lastInteractionAt = now
    }

    fun onBackground(now: Long) {
        if (backgroundedAt == null) backgroundedAt = now
    }

    /** ON_START: returns the reason to lock before the first frame, or null to stay open. */
    fun onForeground(now: Long): Reason? {
        val since = backgroundedAt
        backgroundedAt = null
        if (since != null && now - since >= backgroundMillis) return Reason.Background
        // Returning to the app counts as interaction.
        lastInteractionAt = now
        return null
    }

    fun onScreenOff(): Reason = Reason.ScreenOff

    /** Periodic / timer check. */
    fun check(now: Long): Reason? {
        val since = backgroundedAt
        return when {
            since != null -> if (now - since >= backgroundMillis) Reason.Background else null
            now - lastInteractionAt >= idleMillis -> Reason.Idle
            else -> null
        }
    }

    /** Elapsed-realtime at which [check] will next return a reason (for scheduling a timer). */
    fun nextDeadline(): Long {
        val since = backgroundedAt
        return if (since != null) since + backgroundMillis else lastInteractionAt + idleMillis
    }

    companion object {
        const val BACKGROUND_MILLIS = 60_000L
        const val IDLE_MILLIS = 5 * 60_000L
    }
}
