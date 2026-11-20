package com.nnikolovskii.vault.domain

/**
 * ISO/IEC 7816-4 padding (`0x80`, then zeros) to a multiple of [BLOCK] bytes, minimum [BLOCK].
 * The blob length then says "short" or "long", not the exact secret length.
 */
object Padding {
    const val BLOCK = 64

    fun paddedLength(length: Int): Int = ((length / BLOCK) + 1) * BLOCK

    fun pad(input: ByteArray): ByteArray {
        val out = ByteArray(paddedLength(input.size))
        input.copyInto(out)
        out[input.size] = 0x80.toByte()
        return out
    }

    /** @throws IllegalArgumentException on a length or marker that padding could not produce. */
    fun unpad(input: ByteArray): ByteArray {
        require(input.size >= BLOCK && input.size % BLOCK == 0) { "Bad padded length" }
        var i = input.size - 1
        while (i >= 0 && input[i] == 0.toByte()) i--
        require(i >= 0 && input[i] == 0x80.toByte()) { "Bad padding marker" }
        require(input.size - i <= BLOCK) { "Padding longer than one block" }
        return input.copyOf(i)
    }
}
