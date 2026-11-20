package com.nnikolovskii.vault.session

import com.nnikolovskii.vault.crypto.VaultKey
import com.nnikolovskii.vault.testing.FakeDeviceWrap
import com.nnikolovskii.vault.testing.floorHierarchy
import com.nnikolovskii.vault.domain.PassphraseRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test

class VaultSessionTest {
    companion object {
        private lateinit var keySource: () -> VaultKey

        @BeforeClass
        @JvmStatic
        fun setUp() {
            val device = FakeDeviceWrap()
            val h = floorHierarchy(device)
            val created = h.create(PassphraseRules.encode("correct horse battery staple"), 0L)
            val header = created.header
            keySource = {
                (h.unlock(header, PassphraseRules.encode("correct horse battery staple"))
                    as com.nnikolovskii.vault.crypto.UnlockResult.Success).key
            }
        }
    }

    private class Recorder : VaultSession.Listener {
        var unlocked = 0
        var locked = 0
        override fun onUnlocked() { unlocked++ }
        override fun onLocked() { locked++ }
    }

    @Test
    fun lockWipesTheKeyAndNotifies() {
        val s = VaultSession()
        val r = Recorder().also(s::addListener)
        val key = keySource()
        assertTrue(s.completeUnlock(s.beginUnlock(), key, ByteArray(16)))
        assertEquals(SessionState.Unlocked, s.state.value)
        assertEquals(1, r.unlocked)
        s.lock()
        assertEquals(SessionState.Locked, s.state.value)
        assertTrue(key.isWiped)
        assertTrue(key.copyBytes().all { it == 0.toByte() })
        assertEquals(1, r.locked)
        try {
            s.withKey { }
            fail("withKey after lock")
        } catch (_: VaultLockedException) {
        }
    }

    @Test
    fun lockDuringUnlockDiscardsTheResult() {
        val s = VaultSession()
        s.setResting(SessionState.Locked)
        val token = s.beginUnlock()
        assertEquals(SessionState.Unlocking, s.state.value)
        s.lock() // screen off while the KDF runs
        val key = keySource()
        assertFalse(s.completeUnlock(token, key, ByteArray(16)))
        assertTrue(key.isWiped)
        assertEquals(SessionState.Locked, s.state.value)
        assertFalse(s.isUnlocked)
    }

    @Test
    fun createKeepsItsScreenAndALockDuringCreateDiscardsTheKey() {
        val s = VaultSession()
        s.setResting(SessionState.NoVault)
        val token = s.beginUnlock(announce = false)
        assertEquals(SessionState.NoVault, s.state.value)
        s.lock()
        val key = keySource()
        assertFalse(s.completeUnlock(token, key, ByteArray(16)))
        assertTrue(key.isWiped)
    }

    @Test
    fun lockWhileLockedIsQuiet() {
        val s = VaultSession()
        val r = Recorder().also(s::addListener)
        s.setResting(SessionState.Locked)
        s.lock()
        assertEquals(0, r.locked)
        assertEquals(SessionState.Locked, s.state.value)
    }

    @Test
    fun failedUnlockReturnsToLocked() {
        val s = VaultSession()
        s.setResting(SessionState.Locked)
        s.failUnlock(s.beginUnlock())
        assertEquals(SessionState.Locked, s.state.value)
    }
}
