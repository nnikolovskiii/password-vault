package com.nnikolovskii.vault.session

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import com.nnikolovskii.vault.VaultApp

/**
 * Started (not foreground, no notification, no permission) while the vault is unlocked.
 *
 * Without it, leaving the app makes the process cached, and Android 14+ freezes cached processes
 * within seconds, so the 30 s clipboard clear and the 60 s background lock would not run until
 * Nikola came back. A started service keeps the process out of the cached state until Android
 * stops idle background services (about a minute after leaving). If Android stops it while the
 * vault is open in the background, that is a background timeout: lock.
 */
class SessionService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY

    override fun onDestroy() {
        val app = application as VaultApp
        val inForeground = ProcessLifecycleOwner.get().lifecycle.currentState
            .isAtLeast(Lifecycle.State.STARTED)
        if (!inForeground && !stoppingOnPurpose) app.session.lock()
        stoppingOnPurpose = false
        super.onDestroy()
    }

    companion object {
        @Volatile
        private var stoppingOnPurpose = false

        fun start(context: Context) {
            try {
                context.startService(Intent(context, SessionService::class.java))
            } catch (_: IllegalStateException) {
                // Background start not allowed (unlock finished after leaving): nothing to keep.
            }
        }

        fun stop(context: Context) {
            stoppingOnPurpose = true
            if (!context.stopService(Intent(context, SessionService::class.java))) {
                stoppingOnPurpose = false
            }
        }
    }
}
