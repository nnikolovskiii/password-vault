package com.nnikolovskii.vault.testing

import com.nnikolovskii.vault.crypto.Aead
import com.nnikolovskii.vault.crypto.AeadException
import com.nnikolovskii.vault.crypto.Argon2Kdf
import com.nnikolovskii.vault.crypto.BiometricKey
import com.nnikolovskii.vault.crypto.BiometricKeyInvalidatedException
import com.nnikolovskii.vault.crypto.BiometricUnavailableException
import com.nnikolovskii.vault.crypto.DeviceKeyLostException
import com.nnikolovskii.vault.crypto.DeviceWrap
import com.nnikolovskii.vault.crypto.KdfParams
import com.nnikolovskii.vault.crypto.KeyHierarchy
import com.nnikolovskii.vault.data.EntryDao
import com.nnikolovskii.vault.data.EntryEntity
import com.nnikolovskii.vault.data.VaultMetaDao
import com.nnikolovskii.vault.data.VaultMetaEntity
import com.nnikolovskii.vault.data.VaultRepository
import com.nnikolovskii.vault.domain.Backoff
import com.nnikolovskii.vault.session.BackoffStore
import com.nnikolovskii.vault.session.VaultSession
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map

/** Stands in for the Keystore key: an in-memory AES key, which tests can "lose". */
class FakeDeviceWrap : DeviceWrap {
    override val alias: String = "pv.device.v1"
    private var key: SecretKey? = null

    override fun createKey() {
        key = Aead.key(ByteArray(32).also(SecureRandom()::nextBytes))
    }

    override fun hasKey(): Boolean = key != null

    fun lose() {
        key = null
    }

    override fun wrap(plaintext: ByteArray, aad: ByteArray): ByteArray =
        Aead.encrypt(key ?: throw DeviceKeyLostException(), plaintext, aad)

    override fun unwrap(blob: ByteArray, aad: ByteArray): ByteArray {
        val k = key ?: throw DeviceKeyLostException()
        return try {
            Aead.decrypt(k, blob, aad)
        } catch (e: AeadException) {
            throw DeviceKeyLostException()
        }
    }
}

/**
 * Stands in for `pv.bio.v1`: an ordinary AES key, so the ciphers work without a prompt. Tests can
 * invalidate it (new fingerprint enrolled) or make it unavailable (nothing enrolled).
 */
class FakeBiometricKey : BiometricKey {
    override val alias: String = "pv.bio.v1"
    private var key: SecretKey? = null
    var invalidated = false
    var available = true
    var created = 0

    override fun createKey() {
        if (!available) throw BiometricUnavailableException()
        key = Aead.key(ByteArray(32).also(SecureRandom()::nextBytes))
        invalidated = false
        created++
    }

    override fun deleteKey() {
        key = null
        invalidated = false
    }

    override fun hasKey(): Boolean = key != null

    override fun encryptCipher(): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, usable()) }

    override fun decryptCipher(iv: ByteArray): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, usable(), GCMParameterSpec(128, iv))
        }

    private fun usable(): SecretKey {
        if (invalidated) throw BiometricKeyInvalidatedException()
        return key ?: throw BiometricKeyInvalidatedException()
    }
}

class FakeMetaDao : VaultMetaDao {
    private val flow = MutableStateFlow<VaultMetaEntity?>(null)
    var row: VaultMetaEntity?
        get() = flow.value
        set(value) {
            flow.value = value
        }

    override suspend fun get(): VaultMetaEntity? = row

    override fun observe(): Flow<VaultMetaEntity?> = flow

    override suspend fun insert(meta: VaultMetaEntity) {
        check(row == null) { "UNIQUE constraint failed" }
        row = meta
    }

    override suspend fun clear() {
        row = null
    }

    override suspend fun updateKdf(
        algorithm: String,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int,
        wrappedVaultKey: ByteArray,
        alias: String,
    ): Int {
        val r = row ?: return 0
        row = VaultMetaEntity(
            r.id, r.vaultId, r.formatVersion, algorithm, salt, memoryKib, iterations, parallelism,
            wrappedVaultKey, alias, r.createdAt, r.backupInfo, r.biometricWrap, r.passphraseInfo, r.settings,
        )
        return 1
    }

    override suspend fun setBackupInfo(blob: ByteArray?): Int = update { it.copy(backupInfo = blob) }

    override suspend fun setBiometricWrap(blob: ByteArray?): Int = update { it.copy(biometricWrap = blob) }

    override suspend fun setPassphraseInfo(blob: ByteArray?): Int = update { it.copy(passphraseInfo = blob) }

    override suspend fun setSettings(blob: ByteArray?): Int = update { it.copy(settings = blob) }

    private fun update(change: (Columns) -> Columns): Int {
        val r = row ?: return 0
        val c = change(Columns(r.backupInfo, r.biometricWrap, r.passphraseInfo, r.settings))
        row = VaultMetaEntity(
            r.id, r.vaultId, r.formatVersion, r.kdfAlgorithm, r.kdfSalt, r.kdfMemoryKib,
            r.kdfIterations, r.kdfParallelism, r.wrappedVaultKey, r.deviceKeyAlias, r.createdAt,
            c.backupInfo, c.biometricWrap, c.passphraseInfo, c.settings,
        )
        return 1
    }

    private data class Columns(
        val backupInfo: ByteArray?,
        val biometricWrap: ByteArray?,
        val passphraseInfo: ByteArray?,
        val settings: ByteArray?,
    )
}

class FakeEntryDao : EntryDao {
    val rows = MutableStateFlow<Map<String, EntryEntity>>(emptyMap())

    override fun observeAll(): Flow<List<EntryEntity>> = rows.map { it.values.toList() }

    override suspend fun get(id: String): EntryEntity? = rows.value[id]

    override suspend fun all(): List<EntryEntity> = rows.value.values.toList()

    override suspend fun insertAll(entries: List<EntryEntity>) {
        for (e in entries) check(!rows.value.containsKey(e.id)) { "UNIQUE constraint failed" }
        rows.value = rows.value + entries.associateBy { it.id }
    }

    override suspend fun deleteAll() {
        rows.value = emptyMap()
    }

    override suspend fun upsert(entry: EntryEntity) {
        rows.value = rows.value + (entry.id to entry)
    }

    override suspend fun delete(id: String): Int {
        val had = rows.value.containsKey(id)
        rows.value = rows.value - id
        return if (had) 1 else 0
    }

    fun put(entry: EntryEntity) {
        rows.value = rows.value + (entry.id to entry)
    }
}

class MemoryBackoffStore : BackoffStore {
    var value = Backoff()
    override fun load(): Backoff = value
    override fun save(backoff: Backoff) {
        value = backoff
    }
}

/** Real Argon2id at the floor (64 MiB, t = 3); only calibration is skipped. */
fun floorHierarchy(deviceWrap: DeviceWrap): KeyHierarchy = KeyHierarchy(
    kdf = Argon2Kdf,
    deviceWrap = deviceWrap,
    chooseIterations = { KdfParams.MIN_ITERATIONS },
    clock = System::currentTimeMillis,
)

class TestVault(
    val deviceWrap: FakeDeviceWrap = FakeDeviceWrap(),
    val biometricKey: FakeBiometricKey = FakeBiometricKey(),
    val metaDao: FakeMetaDao = FakeMetaDao(),
    val entryDao: FakeEntryDao = FakeEntryDao(),
    val session: VaultSession = VaultSession(),
    val backoff: MemoryBackoffStore = MemoryBackoffStore(),
    var now: Long = 1_700_000_000_000L,
) {
    val hierarchy = floorHierarchy(deviceWrap)
    val repository = VaultRepository(
        metaDao = metaDao,
        entryDao = entryDao,
        hierarchy = hierarchy,
        deviceWrap = deviceWrap,
        biometricKey = biometricKey,
        session = session,
        backoffStore = backoff,
        wallClock = { now },
        kdfDispatcher = Dispatchers.Default,
    )
}

fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)

/** True when [needle] occurs anywhere in [haystack]. */
fun ByteArray.containsBytes(needle: ByteArray): Boolean {
    if (needle.isEmpty() || needle.size > size) return false
    outer@ for (i in 0..size - needle.size) {
        for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
        return true
    }
    return false
}
