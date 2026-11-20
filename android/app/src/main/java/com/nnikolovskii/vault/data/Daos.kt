package com.nnikolovskii.vault.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

@Dao
interface VaultMetaDao {
    @Query("SELECT * FROM vault_meta WHERE id = 1")
    suspend fun get(): VaultMetaEntity?

    @Query("SELECT * FROM vault_meta WHERE id = 1")
    fun observe(): Flow<VaultMetaEntity?>

    /** ABORT: a second vault_meta row must never silently replace the first. */
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(meta: VaultMetaEntity)

    /** Restore over a Device-key-lost vault: the old row's device wrap is dead anyway. */
    @Query("DELETE FROM vault_meta")
    suspend fun clear()

    /** Change passphrase. Touches only the KDF header and the wrap, never [VaultMetaEntity.backupInfo]. */
    @Query(
        "UPDATE vault_meta SET kdfAlgorithm = :algorithm, kdfSalt = :salt, kdfMemoryKib = :memoryKib, " +
            "kdfIterations = :iterations, kdfParallelism = :parallelism, " +
            "wrappedVaultKey = :wrappedVaultKey, deviceKeyAlias = :alias WHERE id = 1",
    )
    suspend fun updateKdf(
        algorithm: String,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int,
        wrappedVaultKey: ByteArray,
        alias: String,
    ): Int

    @Query("UPDATE vault_meta SET backupInfo = :blob WHERE id = 1")
    suspend fun setBackupInfo(blob: ByteArray?): Int

    @Query("UPDATE vault_meta SET biometricWrap = :blob WHERE id = 1")
    suspend fun setBiometricWrap(blob: ByteArray?): Int

    @Query("UPDATE vault_meta SET passphraseInfo = :blob WHERE id = 1")
    suspend fun setPassphraseInfo(blob: ByteArray?): Int

    @Query("UPDATE vault_meta SET settings = :blob WHERE id = 1")
    suspend fun setSettings(blob: ByteArray?): Int
}

@Dao
interface EntryDao {
    @Query("SELECT * FROM entries")
    fun observeAll(): Flow<List<EntryEntity>>

    @Query("SELECT * FROM entries")
    suspend fun all(): List<EntryEntity>

    @Query("SELECT * FROM entries WHERE id = :id")
    suspend fun get(id: String): EntryEntity?

    @Upsert
    suspend fun upsert(entry: EntryEntity)

    /** Restore: ABORT, because the table was just emptied and ids in a file are unique. */
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertAll(entries: List<EntryEntity>)

    /** Hard delete. With secure_delete on, freed pages are zeroed. */
    @Query("DELETE FROM entries WHERE id = :id")
    suspend fun delete(id: String): Int

    /** Restore over a Device-key-lost vault of a different vault id. */
    @Query("DELETE FROM entries")
    suspend fun deleteAll()
}
