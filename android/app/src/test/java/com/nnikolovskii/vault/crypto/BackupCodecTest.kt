package com.nnikolovskii.vault.crypto

import java.security.SecureRandom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Structure and MAC of `.pvault` files, without the KDF (the repository tests run that). */
class BackupCodecTest {
    private val random = SecureRandom()
    private fun bytes(n: Int) = ByteArray(n).also(random::nextBytes)

    private val header = VaultHeader(
        vaultId = bytes(16),
        formatVersion = 1,
        kdfAlgorithm = "argon2id-v19",
        kdfSalt = bytes(16),
        kdfMemoryKib = 65_536,
        kdfIterations = 4,
        kdfParallelism = 1,
        wrappedVaultKey = bytes(90),
        deviceKeyAlias = "pv.device.v1",
        createdAt = 1_700_000_000_000L,
    )
    private val pwWrap = bytes(61)
    private val macKey = bytes(32)
    private val entries = listOf(
        BackupEntry("6f1c1d2e-0000-4000-8000-000000000001", 1, bytes(93), bytes(93)),
        BackupEntry("6f1c1d2e-0000-4000-8000-000000000002", 1, bytes(157), bytes(221)),
    )
    private val file = BackupCodec.encode(header, pwWrap, entries, exportedAt = 1_760_000_000_000L, macKey = macKey)

    /** True only when the bytes parse and the MAC verifies. */
    private fun opens(b: ByteArray, key: ByteArray = macKey): Boolean =
        try {
            BackupCodec.verify(BackupCodec.parse(b), key)
        } catch (e: BackupFormatException) {
            false
        }

    @Test
    fun roundTrip() {
        val parsed = BackupCodec.parse(file)
        assertTrue(BackupCodec.verify(parsed, macKey))
        assertArrayEquals(header.vaultId, parsed.vaultId)
        assertEquals(1, parsed.formatVersion)
        assertEquals("argon2id-v19", parsed.kdfAlgorithm)
        assertArrayEquals(header.kdfSalt, parsed.kdfSalt)
        assertEquals(65_536, parsed.kdfMemoryKib)
        assertEquals(4, parsed.kdfIterations)
        assertEquals(1, parsed.kdfParallelism)
        assertArrayEquals(pwWrap, parsed.pwWrap)
        assertEquals(header.createdAt, parsed.vaultCreatedAt)
        assertEquals(1_760_000_000_000L, parsed.exportedAt)
        assertEquals(2, parsed.entryCount)
        for ((a, b) in entries.zip(parsed.entries)) {
            assertEquals(a.id, b.id)
            assertEquals(a.formatVersion, b.formatVersion)
            assertArrayEquals(a.summaryBlob, b.summaryBlob)
            assertArrayEquals(a.secretBlob, b.secretBlob)
        }
        // The rebuilt header has the same AAD as the vault's own.
        assertArrayEquals(header.headerAad(), parsed.header().headerAad())
    }

    @Test
    fun deviceLayerIsNotInTheFile() {
        assertFalse(contains(file, header.wrappedVaultKey))
        assertTrue(contains(file, pwWrap))
    }

    @Test
    fun emptyVaultRoundTrips() {
        val empty = BackupCodec.encode(header, pwWrap, emptyList(), 1L, macKey)
        val parsed = BackupCodec.parse(empty)
        assertEquals(0, parsed.entryCount)
        assertTrue(BackupCodec.verify(parsed, macKey))
    }

    @Test
    fun everyTruncationIsRejected() {
        for (n in 0 until file.size) {
            assertFalse("prefix of $n bytes", opens(file.copyOf(n)))
        }
    }

    @Test
    fun everySingleBitFlipIsRejected() {
        for (i in file.indices) {
            val edited = file.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            assertFalse("bit flip at $i", opens(edited))
        }
    }

    @Test
    fun trailingBytesAreRejected() {
        assertFalse(opens(file + byteArrayOf(0)))
        assertFalse(opens(file + file))
    }

    @Test
    fun droppedEntryIsRejectedEvenWithAValidStructure() {
        // Someone rebuilds the file without the second entry but cannot recompute the MAC.
        val forged = BackupCodec.encode(header, pwWrap, entries.take(1), 1_760_000_000_000L, bytes(32))
        assertTrue(BackupCodec.parse(forged).entryCount == 1)
        assertFalse(opens(forged))
    }

    @Test
    fun wrongMacKeyIsRejected() {
        assertFalse(opens(file, bytes(32)))
    }

    @Test
    fun notABackupIsAFormatError() {
        for (junk in listOf(ByteArray(0), bytes(10), bytes(4096), "PVAULT".toByteArray())) {
            expectFormatError { BackupCodec.parse(junk) }
        }
    }

    @Test
    fun newerFileVersionIsAFormatError() {
        val newer = file.copyOf().also { it[7] = 2 }
        expectFormatError { BackupCodec.parse(newer) }
    }

    @Test
    fun absurdEntryCountIsRefusedBeforeAllocating() {
        // entryCount sits right after the fixed header: overwrite it with Int.MAX_VALUE.
        val countAt = 8 + 16 + 4 + 1 + 12 + 4 + 4 + 4 + 1 + 16 + 2 + 61 + 8 + 8
        val edited = file.copyOf()
        edited[countAt] = 0x7F
        for (i in 1..3) edited[countAt + i] = 0xFF.toByte()
        expectFormatError { BackupCodec.parse(edited) }
    }

    @Test
    fun duplicateEntryIdsAreAFormatError() {
        val twice = BackupCodec.encode(header, pwWrap, listOf(entries[0], entries[0]), 1L, macKey)
        expectFormatError { BackupCodec.parse(twice) }
    }

    private fun expectFormatError(block: () -> Unit) {
        try {
            block()
            fail("expected BackupFormatException")
        } catch (_: BackupFormatException) {
        }
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }
}
