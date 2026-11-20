package com.nnikolovskii.vault.crypto

import com.nnikolovskii.vault.domain.Aad
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * The 32-byte vault key. Lives only in memory while the session is Unlocked; [wipe] zeroes it and
 * drops the JCA key object (whose internal copy cannot be zeroed, see PLAN.md).
 */
class VaultKey internal constructor(bytes: ByteArray) {
    private val bytes: ByteArray = bytes
    private var spec: SecretKey? = Aead.key(bytes)

    val isWiped: Boolean get() = spec == null

    fun secretKey(): SecretKey = spec ?: throw IllegalStateException("Vault is locked")

    fun wipe() {
        Wipe.bytes(bytes)
        spec = null
    }

    /** Constant-time: do both objects hold the same (unwiped) key? */
    fun sameAs(other: VaultKey): Boolean =
        !isWiped && !other.isWiped && Hkdf.equal(bytes, other.bytes)

    /** HMAC key for `.pvault` files (HKDF, info `pv1 export`). The caller wipes it. */
    fun exportMacKey(): ByteArray {
        check(!isWiped) { "Vault is locked" }
        return BackupCodec.macKey(bytes)
    }

    /** Biometric wrap of this key with an authenticated cipher from [BiometricKey.encryptCipher]. */
    fun sealWithBiometric(cipher: Cipher, aad: ByteArray): ByteArray {
        check(!isWiped) { "Vault is locked" }
        return BiometricSeal.seal(cipher, bytes, aad)
    }

    /** Passphrase wrap of this key under [kek] (the pwWrap). */
    internal fun sealUnder(kek: SecretKey, aad: ByteArray): ByteArray {
        check(!isWiped) { "Vault is locked" }
        return Aead.encrypt(kek, bytes, aad)
    }

    /** Tests only: compare two keys without exposing them to the app. */
    internal fun copyBytes(): ByteArray = bytes.copyOf()

    override fun toString(): String = "VaultKey(redacted)"
}

/** Everything `vault_meta` stores. Not secret, but integrity-bound through the AADs. */
class VaultHeader(
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
) {
    fun copy(
        vaultId: ByteArray = this.vaultId,
        formatVersion: Int = this.formatVersion,
        kdfAlgorithm: String = this.kdfAlgorithm,
        kdfSalt: ByteArray = this.kdfSalt,
        kdfMemoryKib: Int = this.kdfMemoryKib,
        kdfIterations: Int = this.kdfIterations,
        kdfParallelism: Int = this.kdfParallelism,
        wrappedVaultKey: ByteArray = this.wrappedVaultKey,
        deviceKeyAlias: String = this.deviceKeyAlias,
        createdAt: Long = this.createdAt,
    ) = VaultHeader(
        vaultId, formatVersion, kdfAlgorithm, kdfSalt, kdfMemoryKib, kdfIterations,
        kdfParallelism, wrappedVaultKey, deviceKeyAlias, createdAt,
    )

    fun headerAad(): ByteArray = Aad.header(
        formatVersion, vaultId, kdfAlgorithm, kdfMemoryKib, kdfIterations, kdfParallelism, kdfSalt,
    )

    override fun toString(): String =
        "VaultHeader(v=$formatVersion, $kdfAlgorithm, m=$kdfMemoryKib, t=$kdfIterations, p=$kdfParallelism)"
}

sealed interface UnlockResult {
    class Success(val key: VaultKey, val kdfMillis: Long) : UnlockResult {
        override fun toString(): String = "Success(kdfMillis=$kdfMillis)"
    }

    class WrongPassphrase(val kdfMillis: Long) : UnlockResult

    /** The Keystore key is missing or invalid. No passphrase can open this vault on this phone. */
    data object DeviceKeyLost : UnlockResult

    /** The phone itself is locked; try again once it is unlocked. */
    data object DeviceLocked : UnlockResult
}

class CreatedVault(val header: VaultHeader, val key: VaultKey, val kdfMillis: Long) {
    override fun toString(): String = "CreatedVault($header)"
}

/** Export and change passphrase prove the passphrase again; this is the answer. */
sealed interface Reauth {
    /** The caller wipes both [key] and [pwWrap] (see [wipe]). */
    class Ok(val key: VaultKey, val pwWrap: ByteArray, val kdfMillis: Long) : Reauth {
        fun wipe() {
            key.wipe()
            Wipe.bytes(pwWrap)
        }

        override fun toString(): String = "Reauth.Ok(redacted)"
    }

    class WrongPassphrase(val kdfMillis: Long) : Reauth
    data object DeviceKeyLost : Reauth
    data object DeviceLocked : Reauth
}

/** Opening a `.pvault` file with a passphrase. */
sealed interface BackupOpen {
    class Success(val key: VaultKey, val kdfMillis: Long) : BackupOpen {
        override fun toString(): String = "BackupOpen.Success(kdfMillis=$kdfMillis)"
    }

    /** Wrong passphrase, or an edited header (indistinguishable on purpose). */
    data object WrongPassphrase : BackupOpen

    /** The passphrase opened it but the whole-file MAC failed: entries edited or swapped. */
    data object Damaged : BackupOpen

    /** A format version or KDF this version does not know, or absurd parameters. */
    data object Unsupported : BackupOpen
}

class ChangedHeader(val header: VaultHeader, val kdfMillis: Long) {
    override fun toString(): String = "ChangedHeader($header)"
}

/**
 * Create and unlock, pure over [Kdf] and [DeviceWrap]:
 *
 * ```
 * passphrase ─NFC→UTF-8─▶ Argon2id ─▶ KEK
 * VK ─AES-GCM(KEK, headerAad)─▶ pwWrap ─AES-GCM(device key, vaultId)─▶ wrappedVaultKey
 * ```
 *
 * Every passphrase / KEK / pwWrap buffer is wiped before returning. The caller owns the
 * passphrase bytes it passes in and wipes them too.
 */
class KeyHierarchy(
    private val kdf: Kdf,
    private val deviceWrap: DeviceWrap,
    /** Chooses `t` for a new vault from its salt. Never below 3 (the calibrator guarantees it). */
    private val chooseIterations: (salt: ByteArray) -> Int,
    /** Monotonic milliseconds, for the debug KDF timing. */
    private val clock: () -> Long,
    private val random: SecureRandom = SecureRandom(),
) {
    fun create(passphrase: ByteArray, createdAt: Long): CreatedVault {
        val vaultId = randomBytes(VAULT_ID_BYTES)
        val salt = randomBytes(KdfParams.SALT_BYTES)
        val vk = randomBytes(KdfParams.KEY_BYTES)
        val iterations = chooseIterations(salt).coerceAtLeast(KdfParams.MIN_ITERATIONS)
        val params = KdfParams(KdfParams.MEMORY_KIB, iterations, KdfParams.PARALLELISM, salt)
        val draft = VaultHeader(
            vaultId = vaultId,
            formatVersion = FORMAT_VERSION,
            kdfAlgorithm = KDF_ALGORITHM,
            kdfSalt = salt,
            kdfMemoryKib = params.memoryKib,
            kdfIterations = params.iterations,
            kdfParallelism = params.parallelism,
            wrappedVaultKey = ByteArray(0),
            deviceKeyAlias = deviceWrap.alias,
            createdAt = createdAt,
        )

        val start = clock()
        val kek = kdf.derive(passphrase, params)
        val kdfMillis = clock() - start
        val pwWrap = try {
            Aead.encrypt(Aead.key(kek), vk, draft.headerAad())
        } finally {
            Wipe.bytes(kek)
        }
        val wrapped = try {
            deviceWrap.createKey()
            deviceWrap.wrap(pwWrap, vaultId)
        } catch (t: Throwable) {
            Wipe.bytes(vk)
            throw t
        } finally {
            Wipe.bytes(pwWrap)
        }
        return CreatedVault(draft.copy(wrappedVaultKey = wrapped), VaultKey(vk), kdfMillis)
    }

    fun unlock(header: VaultHeader, passphrase: ByteArray): UnlockResult =
        when (val r = reauthenticate(header, passphrase)) {
            is Reauth.Ok -> {
                Wipe.bytes(r.pwWrap)
                UnlockResult.Success(r.key, r.kdfMillis)
            }
            is Reauth.WrongPassphrase -> UnlockResult.WrongPassphrase(r.kdfMillis)
            Reauth.DeviceKeyLost -> UnlockResult.DeviceKeyLost
            Reauth.DeviceLocked -> UnlockResult.DeviceLocked
        }

    /**
     * Device unwrap, then Argon2id. On success the caller gets the VK and the passphrase wrap
     * (pwWrap, no device layer) and wipes both.
     */
    fun reauthenticate(header: VaultHeader, passphrase: ByteArray): Reauth {
        // 1. Device layer first: a lost key means no passphrase prompt is useful.
        val pwWrap = try {
            deviceWrap.unwrap(header.wrappedVaultKey, header.vaultId)
        } catch (e: DeviceLockedException) {
            return Reauth.DeviceLocked
        } catch (e: DeviceKeyLostException) {
            return Reauth.DeviceKeyLost
        }
        // 2. A header we do not understand (or that would exhaust memory) cannot be opened.
        if (!plausible(header)) {
            Wipe.bytes(pwWrap)
            return Reauth.WrongPassphrase(0)
        }
        // 3. Any tampered header field changes the AAD (and maybe the KEK): the tag fails.
        val (key, kdfMillis) = openPwWrap(header, pwWrap, passphrase)
        if (key == null) {
            Wipe.bytes(pwWrap)
            return Reauth.WrongPassphrase(kdfMillis)
        }
        return Reauth.Ok(key, pwWrap, kdfMillis)
    }

    /**
     * Change passphrase: new salt, re-calibrated `t`, new pwWrap of the same [key], device-wrapped
     * with the existing device key (replacing that key here could strand the stored wrap if the
     * write that follows failed). Entries are untouched. [newPassphrase] is the caller's to wipe.
     */
    fun changePassphrase(header: VaultHeader, key: VaultKey, newPassphrase: ByteArray): ChangedHeader {
        val salt = randomBytes(KdfParams.SALT_BYTES)
        val iterations = chooseIterations(salt).coerceAtLeast(KdfParams.MIN_ITERATIONS)
        val params = KdfParams(KdfParams.MEMORY_KIB, iterations, KdfParams.PARALLELISM, salt)
        val draft = header.copy(
            kdfAlgorithm = KDF_ALGORITHM,
            formatVersion = FORMAT_VERSION,
            kdfSalt = salt,
            kdfMemoryKib = params.memoryKib,
            kdfIterations = params.iterations,
            kdfParallelism = params.parallelism,
            wrappedVaultKey = ByteArray(0),
        )
        val start = clock()
        val kek = kdf.derive(newPassphrase, params)
        val kdfMillis = clock() - start
        val pwWrap = try {
            key.sealUnder(Aead.key(kek), draft.headerAad())
        } finally {
            Wipe.bytes(kek)
        }
        val wrapped = try {
            deviceWrap.wrap(pwWrap, header.vaultId)
        } finally {
            Wipe.bytes(pwWrap)
        }
        return ChangedHeader(draft.copy(wrappedVaultKey = wrapped), kdfMillis)
    }

    /** Builds a `.pvault` file from an [Reauth.Ok] (so the passphrase was just proven). */
    fun exportFile(header: VaultHeader, proof: Reauth.Ok, entries: List<BackupEntry>, exportedAt: Long): ByteArray {
        val macKey = proof.key.exportMacKey()
        try {
            return BackupCodec.encode(header, proof.pwWrap, entries, exportedAt, macKey)
        } finally {
            Wipe.bytes(macKey)
        }
    }

    /** Passphrase → VK from the file's own header, then the whole-file MAC. */
    fun openBackup(file: BackupFile, passphrase: ByteArray): BackupOpen {
        if (file.formatVersion != FORMAT_VERSION || file.kdfAlgorithm != KDF_ALGORITHM) {
            return BackupOpen.Unsupported
        }
        val header = file.header()
        if (!plausibleBackup(header, file.pwWrap)) return BackupOpen.Unsupported
        val (key, kdfMillis) = openPwWrap(header, file.pwWrap, passphrase)
        key ?: return BackupOpen.WrongPassphrase
        val macKey = key.exportMacKey()
        val ok = try {
            BackupCodec.verify(file, macKey)
        } finally {
            Wipe.bytes(macKey)
        }
        if (!ok) {
            key.wipe()
            return BackupOpen.Damaged
        }
        return BackupOpen.Success(key, kdfMillis)
    }

    /**
     * Restore: a fresh device key on this phone (replacing a lost one), device-wrapping the
     * file's pwWrap. Call only after [openBackup] succeeded for [file].
     */
    fun adoptBackup(file: BackupFile): VaultHeader {
        deviceWrap.createKey()
        val wrapped = deviceWrap.wrap(file.pwWrap, file.vaultId)
        return file.header(wrappedVaultKey = wrapped, deviceKeyAlias = deviceWrap.alias)
    }

    /** Argon2id with the header's params, then the pwWrap tag. Null key: wrong passphrase. */
    private fun openPwWrap(header: VaultHeader, pwWrap: ByteArray, passphrase: ByteArray): Pair<VaultKey?, Long> {
        val params = KdfParams(
            header.kdfMemoryKib, header.kdfIterations, header.kdfParallelism, header.kdfSalt,
        )
        val start = clock()
        val kek = kdf.derive(passphrase, params)
        val kdfMillis = clock() - start
        return try {
            val vk = Aead.decrypt(Aead.key(kek), pwWrap, header.headerAad())
            if (vk.size != KdfParams.KEY_BYTES) {
                Wipe.bytes(vk)
                null to kdfMillis
            } else {
                VaultKey(vk) to kdfMillis
            }
        } catch (e: AeadException) {
            null to kdfMillis
        } finally {
            Wipe.bytes(kek)
        }
    }

    /** A backup is someone else's file until proven: tighter memory bound than a stored header. */
    private fun plausibleBackup(h: VaultHeader, pwWrap: ByteArray): Boolean =
        plausible(h) &&
            h.kdfMemoryKib in KdfParams.MEMORY_KIB..MAX_BACKUP_MEMORY_KIB &&
            h.kdfIterations >= KdfParams.MIN_ITERATIONS &&
            pwWrap.size == Aead.OVERHEAD + KdfParams.KEY_BYTES

    private fun plausible(h: VaultHeader): Boolean =
        h.kdfAlgorithm == KDF_ALGORITHM &&
            h.kdfSalt.size == KdfParams.SALT_BYTES &&
            h.vaultId.size == VAULT_ID_BYTES &&
            h.kdfMemoryKib in 8 * h.kdfParallelism..KdfParams.MAX_STORED_MEMORY_KIB &&
            h.kdfIterations in 1..KdfParams.MAX_STORED_ITERATIONS &&
            h.kdfParallelism in 1..KdfParams.MAX_STORED_PARALLELISM

    private fun randomBytes(n: Int) = ByteArray(n).also(random::nextBytes)

    companion object {
        const val FORMAT_VERSION = 1
        const val KDF_ALGORITHM = "argon2id-v19"
        const val VAULT_ID_BYTES = 16

        /** 256 MiB: the most a restored file may ask Argon2id for. */
        const val MAX_BACKUP_MEMORY_KIB = 262_144
    }
}
