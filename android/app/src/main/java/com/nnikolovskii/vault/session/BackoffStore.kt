package com.nnikolovskii.vault.session

import android.content.Context
import com.nnikolovskii.vault.domain.Backoff

/** Where the wrong-passphrase count and deadline live. Plain storage on purpose (see PLAN.md). */
interface BackoffStore {
    fun load(): Backoff

    fun save(backoff: Backoff)
}

class PrefsBackoffStore(context: Context) : BackoffStore {
    private val prefs = context.getSharedPreferences("vault_backoff", Context.MODE_PRIVATE)

    override fun load(): Backoff =
        Backoff(prefs.getInt(KEY_FAILURES, 0), prefs.getLong(KEY_DEADLINE, 0L))

    override fun save(backoff: Backoff) {
        prefs.edit()
            .putInt(KEY_FAILURES, backoff.failures)
            .putLong(KEY_DEADLINE, backoff.deadlineMillis)
            .commit()
    }

    private companion object {
        const val KEY_FAILURES = "failures"
        const val KEY_DEADLINE = "deadline"
    }
}
