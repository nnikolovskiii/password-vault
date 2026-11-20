package com.nnikolovskii.vault.crypto

/**
 * Picks `t` at create time: the largest `t ≤ 10` that finishes in about [targetMillis] on this
 * phone, never below the floor of 3. Measures one run at the floor and scales linearly (Argon2
 * cost is linear in `t` at fixed memory).
 */
class KdfCalibrator(
    private val kdf: Kdf,
    /** Monotonic clock in milliseconds (SystemClock.elapsedRealtime on device). */
    private val clock: () -> Long,
    private val targetMillis: Long = 1_000,
) {
    /** Result of a calibration: the chosen `t` and how long the floor run took. */
    class Calibration(val iterations: Int, val floorMillis: Long)

    fun calibrate(salt: ByteArray): Calibration {
        val probe = ByteArray(32) { 0x5A }
        val floor = KdfParams(
            KdfParams.MEMORY_KIB,
            KdfParams.MIN_ITERATIONS,
            KdfParams.PARALLELISM,
            salt,
        )
        val start = clock()
        Wipe.bytes(kdf.derive(probe, floor))
        val floorMillis = (clock() - start).coerceAtLeast(1)
        return Calibration(choose(floorMillis, targetMillis), floorMillis)
    }

    companion object {
        /** Pure decision: `t` from the measured floor time. Never < 3, never > 10. */
        fun choose(floorMillis: Long, targetMillis: Long): Int {
            val perIteration = floorMillis.toDouble() / KdfParams.MIN_ITERATIONS
            val fit = if (perIteration <= 0.0) KdfParams.MAX_ITERATIONS
            else (targetMillis / perIteration).toInt()
            return fit.coerceIn(KdfParams.MIN_ITERATIONS, KdfParams.MAX_ITERATIONS)
        }
    }
}
