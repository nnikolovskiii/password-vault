package com.nnikolovskii.vault.crypto

/**
 * Zeroing helpers for buffers we own. Strings and JCA key copies cannot be wiped; see PLAN.md
 * "Perfect memory hygiene". Wipe what we can, as soon as it is no longer needed.
 */
object Wipe {
    fun bytes(vararg buffers: ByteArray?) {
        for (b in buffers) b?.fill(0)
    }

    fun chars(vararg buffers: CharArray?) {
        for (c in buffers) c?.fill('\u0000')
    }
}

/** Runs [block] with [buffer], then zeroes it whether or not [block] threw. */
inline fun <R> ByteArray.useThenWipe(block: (ByteArray) -> R): R =
    try {
        block(this)
    } finally {
        fill(0)
    }
