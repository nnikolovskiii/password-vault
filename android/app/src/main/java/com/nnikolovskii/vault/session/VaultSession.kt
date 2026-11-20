package com.nnikolovskii.vault.session

import com.nnikolovskii.vault.crypto.VaultKey
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

sealed interface SessionState {
    /** Reading vault_meta at launch. */
    data object Loading : SessionState

    /** No vault_meta row: show Create. */
    data object NoVault : SessionState

    data object Locked : SessionState

    /** KDF running. A lock in the meantime discards the result. */
    data object Unlocking : SessionState

    data object Unlocked : SessionState

    /** The Keystore key is gone: no passphrase prompt (recovery is Part 2 restore). */
    data object DeviceKeyLost : SessionState
}

class VaultLockedException : IllegalStateException("Vault is locked")

/**
 * App-scoped session state machine. Holds the vault key while Unlocked and nowhere else; the UI
 * only ever sees [state]. Process death is a lock by construction.
 */
class VaultSession {
    interface Listener {
        fun onUnlocked() {}

        fun onLocked() {}
    }

    /** What an unlocked session holds. Neither part ever leaves this package's callers. */
    class Unlocked internal constructor(val key: VaultKey, vaultId: ByteArray) {
        val vaultId: ByteArray = vaultId.copyOf()

        override fun toString(): String = "Unlocked(redacted)"
    }

    private val _state = MutableStateFlow<SessionState>(SessionState.Loading)
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private val listeners = CopyOnWriteArrayList<Listener>()
    private var current: Unlocked? = null

    /** Bumped on every lock, so an unlock that finishes after a lock is dropped. */
    private var generation = 0L

    val isUnlocked: Boolean get() = synchronized(this) { current != null }

    fun addListener(listener: Listener) {
        listeners += listener
    }

    @Synchronized
    fun setResting(state: SessionState) {
        require(state != SessionState.Unlocked && state != SessionState.Unlocking)
        current?.key?.wipe()
        current = null
        _state.value = state
    }

    /**
     * @param announce false for Create, which keeps its own "Securing your vault…" screen up.
     * @return a token for [completeUnlock].
     */
    @Synchronized
    fun beginUnlock(announce: Boolean = true): Long {
        if (announce) _state.value = SessionState.Unlocking
        return generation
    }

    /** Back to Locked after a failed attempt (wrong passphrase, phone locked). */
    @Synchronized
    fun failUnlock(token: Long) {
        if (token == generation && _state.value == SessionState.Unlocking) {
            _state.value = SessionState.Locked
        }
    }

    /**
     * Installs [key]. If a lock happened since [token] was issued, the key is wiped instead.
     * @return true when the session is now Unlocked.
     */
    fun completeUnlock(token: Long, key: VaultKey, vaultId: ByteArray): Boolean {
        synchronized(this) {
            if (token != generation) {
                key.wipe()
                return false
            }
            current?.key?.wipe()
            current = Unlocked(key, vaultId)
            _state.value = SessionState.Unlocked
        }
        listeners.forEach { it.onUnlocked() }
        return true
    }

    /** Manual, screen off, background, idle. Zeroes the VK and tells everyone to drop plaintext. */
    fun lock() {
        val wasOpen: Boolean
        synchronized(this) {
            generation++
            wasOpen = current != null || _state.value == SessionState.Unlocking
            current?.key?.wipe()
            current = null
            if (_state.value == SessionState.Unlocked || _state.value == SessionState.Unlocking) {
                _state.value = SessionState.Locked
            }
        }
        if (wasOpen) listeners.forEach { it.onLocked() }
    }

    /**
     * Runs [block] with the key under the session lock, so a concurrent [lock] cannot zero the
     * key halfway through an encrypt / decrypt. Keep [block] short and CPU-only.
     */
    fun <R> withKey(block: (Unlocked) -> R): R = synchronized(this) {
        block(current ?: throw VaultLockedException())
    }
}
