package com.nnikolovskii.vault.data

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Real migrations only (never a destructive fallback: the phone holds the only copy). The SQL
 * lives in plain lists so the JVM test can run it against the exported schema JSON.
 */
object VaultMigrations {
    /** v1 (0.1.0) → v2 (0.2.0): encrypted backup info. Existing rows get NULL (= never backed up). */
    val SQL_1_2 = listOf("ALTER TABLE `vault_meta` ADD COLUMN `backupInfo` BLOB")

    val MIGRATION_1_2 = object : Migration(1, 2) {
        override fun migrate(db: SupportSQLiteDatabase) {
            SQL_1_2.forEach(db::execSQL)
        }
    }

    /**
     * v2 (0.2.0) → v3 (0.3.0): biometric wrap, last-passphrase info, encrypted settings. NULL in
     * all three means biometric off, passphrase due, default settings.
     */
    val SQL_2_3 = listOf(
        "ALTER TABLE `vault_meta` ADD COLUMN `biometricWrap` BLOB",
        "ALTER TABLE `vault_meta` ADD COLUMN `passphraseInfo` BLOB",
        "ALTER TABLE `vault_meta` ADD COLUMN `settings` BLOB",
    )

    val MIGRATION_2_3 = object : Migration(2, 3) {
        override fun migrate(db: SupportSQLiteDatabase) {
            SQL_2_3.forEach(db::execSQL)
        }
    }

    val ALL: Array<Migration> = arrayOf(MIGRATION_1_2, MIGRATION_2_3)
}

/** Runs a block in one database transaction. Room on the phone; direct in the JVM tests. */
interface Transactor {
    suspend fun <R> run(block: suspend () -> R): R

    object Direct : Transactor {
        override suspend fun <R> run(block: suspend () -> R): R = block()
    }
}
