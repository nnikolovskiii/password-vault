package com.nnikolovskii.vault.data

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.nnikolovskii.vault.crypto.BackupEntry
import com.nnikolovskii.vault.crypto.VaultHeader

/**
 * Exactly one row. Not secret: random ids, KDF params, and the doubly wrapped vault key.
 * Integrity comes from the AADs (see KeyHierarchy). [backupInfo] (v2) is an AEAD blob under the
 * VK holding the last export time and the changed flag; null until the first entry change or
 * export.
 *
 * v3 (Part 3), all nullable:
 * - [biometricWrap]: the VK wrapped by the biometric Keystore key `pv.bio.v1`; null = off.
 * - [passphraseInfo]: when the passphrase was last proven, wrapped by the device key (the 7-day
 *   rule for biometric unlock).
 * - [settings]: lock / clipboard timeouts and generator defaults, AEAD under the VK; null = defaults.
 */
@Entity(tableName = "vault_meta")
class VaultMetaEntity(
    @PrimaryKey val id: Int = SINGLETON_ID,
    val vaultId: ByteArray,
    val formatVersion: Int,
    val kdfAlgorithm: String,
    val kdfSalt: ByteArray,
    val kdfMemoryKib: Int,
    val kdfIterations: Int,
    val kdfParallelism: Int,
    val wrappedVaultKey: ByteArray,
    val deviceKeyAlias: String,
    val createdAt: Long,
    val backupInfo: ByteArray? = null,
    val biometricWrap: ByteArray? = null,
    val passphraseInfo: ByteArray? = null,
    val settings: ByteArray? = null,
) {
    fun toHeader() = VaultHeader(
        vaultId = vaultId,
        formatVersion = formatVersion,
        kdfAlgorithm = kdfAlgorithm,
        kdfSalt = kdfSalt,
        kdfMemoryKib = kdfMemoryKib,
        kdfIterations = kdfIterations,
        kdfParallelism = kdfParallelism,
        wrappedVaultKey = wrappedVaultKey,
        deviceKeyAlias = deviceKeyAlias,
        createdAt = createdAt,
    )

    override fun toString(): String = "VaultMetaEntity(v=$formatVersion, t=$kdfIterations)"

    companion object {
        const val SINGLETON_ID = 1

        fun from(h: VaultHeader, backupInfo: ByteArray? = null, settings: ByteArray? = null) = VaultMetaEntity(
            id = SINGLETON_ID,
            vaultId = h.vaultId,
            formatVersion = h.formatVersion,
            kdfAlgorithm = h.kdfAlgorithm,
            kdfSalt = h.kdfSalt,
            kdfMemoryKib = h.kdfMemoryKib,
            kdfIterations = h.kdfIterations,
            kdfParallelism = h.kdfParallelism,
            wrappedVaultKey = h.wrappedVaultKey,
            deviceKeyAlias = h.deviceKeyAlias,
            createdAt = h.createdAt,
            backupInfo = backupInfo,
            settings = settings,
        )
    }
}

/**
 * One vault entry. [id] is a random UUIDv4; everything the user typed (and when) is inside the
 * two AEAD blobs. New fields go in as codec tags inside the blobs, never as plaintext columns.
 */
@Entity(tableName = "entries")
class EntryEntity(
    @PrimaryKey val id: String,
    val formatVersion: Int,
    val summaryBlob: ByteArray,
    val secretBlob: ByteArray,
) {
    override fun toString(): String = "EntryEntity(id=$id)"

    fun toBackup() = BackupEntry(id, formatVersion, summaryBlob, secretBlob)

    companion object {
        const val FORMAT_VERSION = 1

        fun from(e: BackupEntry) = EntryEntity(e.id, e.formatVersion, e.summaryBlob, e.secretBlob)
    }
}
