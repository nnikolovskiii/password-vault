package com.nnikolovskii.vault.domain

/**
 * When the last `.pvault` export happened and whether entries changed since. When he backs up is
 * metadata too, so this is stored as an AEAD blob (`vault_meta.backupInfo`), never as plaintext.
 *
 * Payload: `[0x01][lastBackupAt int64, -1 = never][changed 0/1]`.
 */
class BackupInfo(
    /** Epoch ms of the last export that reached a file, or null if there never was one. */
    val lastBackupAt: Long?,
    val changedSinceBackup: Boolean,
) {
    fun withChange() = BackupInfo(lastBackupAt, changedSinceBackup = true)

    fun encode(): ByteArray {
        val out = ByteArray(SIZE)
        out[0] = VERSION
        var v = lastBackupAt ?: NEVER
        for (i in 8 downTo 1) {
            out[i] = (v and 0xFF).toByte()
            v = v ushr 8
        }
        out[9] = (if (changedSinceBackup) 1 else 0).toByte()
        return out
    }

    override fun toString(): String = "BackupInfo(redacted)"

    companion object {
        const val VERSION: Byte = 0x01
        const val SIZE = 10
        private const val NEVER = -1L

        /** A vault that was never exported and has not changed. */
        val NONE = BackupInfo(null, changedSinceBackup = false)

        fun decode(bytes: ByteArray): BackupInfo {
            if (bytes.size != SIZE || bytes[0] != VERSION) throw CodecException("Bad backup info")
            var v = 0L
            for (i in 1..8) v = (v shl 8) or (bytes[i].toLong() and 0xFF)
            val changed = when (bytes[9].toInt()) {
                0 -> false
                1 -> true
                else -> throw CodecException("Bad backup info")
            }
            return BackupInfo(if (v == NEVER) null else v, changed)
        }
    }
}

/**
 * "Last backup: N days ago" in the list header, and the reminder: shown when the vault has
 * entries and either was never exported, or changed since an export older than 30 days.
 */
object BackupReminder {
    const val REMIND_AFTER_MILLIS = 30L * 24 * 60 * 60 * 1000
    private const val DAY_MILLIS = 24L * 60 * 60 * 1000

    class Status(
        /** Whole days since the last export (0 = today), or null when there never was one. */
        val daysSinceBackup: Int?,
        val remind: Boolean,
    )

    fun status(info: BackupInfo, entryCount: Int, nowMillis: Long): Status {
        val last = info.lastBackupAt
        // A clock moved backwards reads as "today", never as a negative age.
        val age = if (last == null) null else (nowMillis - last).coerceAtLeast(0)
        val remind = entryCount > 0 && when {
            age == null -> true
            else -> info.changedSinceBackup && age >= REMIND_AFTER_MILLIS
        }
        val days = age?.let { (it / DAY_MILLIS).coerceAtMost(Int.MAX_VALUE.toLong()).toInt() }
        return Status(days, remind)
    }

    fun label(status: Status): String = when (val d = status.daysSinceBackup) {
        null -> "No backup yet"
        0 -> "Last backup: today"
        1 -> "Last backup: yesterday"
        else -> "Last backup: $d days ago"
    }
}
