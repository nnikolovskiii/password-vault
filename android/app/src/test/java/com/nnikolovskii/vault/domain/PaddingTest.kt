package com.nnikolovskii.vault.domain

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class PaddingTest {
    @Test
    fun lengthsAreMultiplesOf64Minimum64() {
        for (n in 0..300) {
            val padded = Padding.pad(ByteArray(n) { 0x41 })
            assertEquals(0, padded.size % 64)
            assertTrue(padded.size >= 64)
            assertTrue(padded.size > n)
            assertArrayEquals(ByteArray(n) { 0x41 }, Padding.unpad(padded))
        }
        assertEquals(64, Padding.pad(ByteArray(0)).size)
        assertEquals(64, Padding.pad(ByteArray(63)).size)
        assertEquals(128, Padding.pad(ByteArray(64)).size)
    }

    @Test
    fun plaintextEndingInZerosOr0x80SurvivesRoundTrip() {
        val tricky = byteArrayOf(1, 0x80.toByte(), 0, 0)
        assertArrayEquals(tricky, Padding.unpad(Padding.pad(tricky)))
    }

    @Test
    fun malformedPaddingIsRejected() {
        val bad = listOf(
            ByteArray(0),
            ByteArray(63),
            ByteArray(65),
            ByteArray(64), // all zeros: no marker
            ByteArray(64).also { it[10] = 0x80.toByte(); it[63] = 1 }, // ends in data, no marker
            ByteArray(128).also { it[10] = 0x80.toByte() }, // padding longer than one block
        )
        for (b in bad) {
            try {
                Padding.unpad(b)
                fail("accepted ${b.size} bytes")
            } catch (_: IllegalArgumentException) {
            }
        }
    }
}
