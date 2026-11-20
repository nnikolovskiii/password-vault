package com.nnikolovskii.vault.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KdfCalibratorTest {
    /** A KDF that "takes" [floorMillis] on a fake clock and records the params it saw. */
    private class TimedKdf(val floorMillis: Long, val clock: LongArray) : Kdf {
        val seen = mutableListOf<KdfParams>()
        override fun derive(passphrase: ByteArray, params: KdfParams): ByteArray {
            seen += params
            clock[0] += floorMillis * params.iterations / KdfParams.MIN_ITERATIONS
            return ByteArray(32)
        }
    }

    private fun calibrate(floorMillis: Long): Pair<KdfCalibrator.Calibration, TimedKdf> {
        val clock = longArrayOf(0)
        val kdf = TimedKdf(floorMillis, clock)
        return KdfCalibrator(kdf, { clock[0] }).calibrate(ByteArray(16)) to kdf
    }

    @Test
    fun neverBelowThreeOnASlowPhone() {
        for (floor in listOf(1_000L, 2_500L, 9_000L, 60_000L)) {
            assertEquals(3, calibrate(floor).first.iterations)
        }
    }

    @Test
    fun neverAboveTenOnAFastPhone() {
        assertEquals(10, calibrate(1L).first.iterations)
        assertEquals(10, calibrate(30L).first.iterations)
    }

    @Test
    fun picksLargestTWithinTarget() {
        // 600 ms for t=3 → 200 ms per pass → 5 passes fit in 1 s.
        assertEquals(5, calibrate(600L).first.iterations)
        // 450 ms → 150 ms per pass → 6.67 → 6.
        assertEquals(6, calibrate(450L).first.iterations)
    }

    @Test
    fun probesAtTheFloorParams() {
        val (result, kdf) = calibrate(500L)
        val probe = kdf.seen.single()
        assertEquals(KdfParams.MEMORY_KIB, probe.memoryKib)
        assertEquals(3, probe.iterations)
        assertEquals(1, probe.parallelism)
        assertEquals(500L, result.floorMillis)
    }

    @Test
    fun chooseIsClampedForEveryInput() {
        for (ms in listOf(0L, 1L, 10L, 100L, 333L, 1_000L, 10_000L, Long.MAX_VALUE / 2)) {
            val t = KdfCalibrator.choose(ms, 1_000)
            assertTrue("t=$t for $ms ms", t in 3..10)
        }
    }
}
