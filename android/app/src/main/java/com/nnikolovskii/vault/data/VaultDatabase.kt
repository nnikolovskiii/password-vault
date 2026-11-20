package com.nnikolovskii.vault.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Schema v1 froze at the first ship (0.1.0); v2 (0.2.0) adds `vault_meta.backupInfo`; v3 (0.3.0)
 * adds `biometricWrap`, `passphraseInfo`, and `settings`. Exported
 * JSON for every version is in app/schemas/. Every change: bump [version], add a real Migration
 * to [VaultMigrations], commit the new exported JSON. Never a destructive fallback: the phone
 * holds the only copy.
 */
@Database(
    entities = [VaultMetaEntity::class, EntryEntity::class],
    version = 3,
    exportSchema = true,
)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun meta(): VaultMetaDao
    abstract fun entries(): EntryDao

    companion object {
        fun create(context: Context): VaultDatabase =
            Room.databaseBuilder(context, VaultDatabase::class.java, "vault.db")
                .addMigrations(*VaultMigrations.ALL)
                // One connection, so the secure_delete pragma below covers every write.
                .setJournalMode(JournalMode.TRUNCATE)
                .addCallback(object : Callback() {
                    override fun onOpen(db: SupportSQLiteDatabase) {
                        db.query("PRAGMA secure_delete = ON").close()
                    }
                })
                .build()
    }

    /** Room transaction for the repository's multi-table writes. */
    val transactor: Transactor
        get() = object : Transactor {
            override suspend fun <R> run(block: suspend () -> R): R = withTransaction { block() }
        }
}
