package com.nnikolovskii.vault.domain

/**
 * Wrong-passphrase backoff: 5 free failures, then 30 s, doubling per further failure, capped at
 * 15 min. Reset on success. No auto-wipe, ever.
 *
 * Only a defense against casual guessing on the phone; Argon2id and the device wrap slow
 * everyone else. The deadline is wall-clock (it has to survive a reboot), so [remainingMillis]
 * clamps to the full delay if the clock was moved backwards.
 */
class Backoff(val failures: Int = 0, val deadlineMillis: Long = 0L) {

    fun onFailure(nowMillis: Long): Backoff {
        val next = failures + 1
        val delay = delayAfter(next)
        return Backoff(next, if (delay == 0L) 0L else nowMillis + delay)
    }

    fun onSuccess(): Backoff = Backoff()

    fun remainingMillis(nowMillis: Long): Long {
        if (deadlineMillis == 0L) return 0L
        val left = deadlineMillis - nowMillis
        if (left <= 0) return 0L
        return minOf(left, delayAfter(failures))
    }

    override fun toString(): String = "Backoff(failures=$failures, deadline=$deadlineMillis)"

    companion object {
        const val FREE_FAILURES = 5
        const val BASE_MILLIS = 30_000L
        const val CAP_MILLIS = 15 * 60_000L

        /** Wait required after [failures] consecutive wrong passphrases. */
        fun delayAfter(failures: Int): Long {
            if (failures < FREE_FAILURES) return 0L
            val doublings = failures - FREE_FAILURES
            if (doublings >= 30) return CAP_MILLIS
            return minOf(BASE_MILLIS shl doublings, CAP_MILLIS)
        }
    }
}
