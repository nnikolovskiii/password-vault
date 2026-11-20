package com.nnikolovskii.vault.crypto

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/** Not a `.pvault` file, an incomplete one, or one this version cannot read. No detail on purpose. */
class BackupFormatException(message: String) : Exception(message)

/** One entry as stored in the vault: random id plus the two AEAD blobs, byte for byte. */
class BackupEntry(
    val id: String,
    val formatVersion: Int,
    val summaryBlob: ByteArray,
    val secretBlob: ByteArray,
) {
    override fun toString(): String = "BackupEntry(id=$id)"
}

/**
 * A parsed `.pvault` file. Everything in it is ciphertext or non-secret header data, so the file
 * is safe on Drive. Until [BackupCodec.verify] passes (which needs the vault key, so the
 * passphrase), every field is unauthenticated: [exportedAt] and [entries] are only good for a
 * preview.
 */
class BackupFile internal constructor(
    val vaultId: ByteArray,
    val formatVersion: Int,
    val kdfAlgorithm: String,
    val kdfSalt: ByteArray,
    val kdfMemoryKib: Int,
    val kdfIterations: Int,
    val kdfParallelism: Int,
    /** Passphrase wrap of the VK: `AES-GCM(KEK, VK, headerAad)`. No device layer. */
    val pwWrap: ByteArray,
    val vaultCreatedAt: Long,
    val exportedAt: Long,
    val entries: List<BackupEntry>,
    private val raw: ByteArray,
) {
    val entryCount: Int get() = entries.size

    /** The vault header this file describes, with a device wrap supplied by the caller. */
    fun header(wrappedVaultKey: ByteArray = ByteArray(0), deviceKeyAlias: String = ""): VaultHeader =
        VaultHeader(
            vaultId = vaultId,
            formatVersion = formatVersion,
            kdfAlgorithm = kdfAlgorithm,
            kdfSalt = kdfSalt,
            kdfMemoryKib = kdfMemoryKib,
            kdfIterations = kdfIterations,
            kdfParallelism = kdfParallelism,
            wrappedVaultKey = wrappedVaultKey,
            deviceKeyAlias = deviceKeyAlias,
            createdAt = vaultCreatedAt,
        )

    internal fun macMatches(macKey: ByteArray): Boolean {
        val signed = raw.size - Hkdf.HASH_BYTES
        val expected = Hkdf.hmac(macKey, raw, 0, signed)
        return Hkdf.equal(expected, raw.copyOfRange(signed, raw.size))
    }

    override fun toString(): String = "BackupFile(entries=$entryCount, exportedAt=$exportedAt)"
}

/**
 * The `.pvault` export format (big-endian):
 *
 * ```
 * magic           8   "PVAULT" 0x00 0x01   (last byte = file version)
 * vaultId        16
 * formatVersion   4
 * kdfAlgorithm    1 + n  (ASCII)
 * kdfMemoryKib    4
 * kdfIterations   4
 * kdfParallelism  4
 * kdfSalt         1 + n
 * pwWrap          2 + n  (passphrase wrap only, never the device layer)
 * vaultCreatedAt  8      (epoch ms)
 * exportedAt      8      (epoch ms)
 * entryCount      4
 * entryCount × { id 1 + n (ASCII), formatVersion 4, summaryBlob 4 + n, secretBlob 4 + n }
 * mac            32      HMAC-SHA256(HKDF-SHA256(VK, salt = ∅, info = "pv1 export"), all bytes above)
 * ```
 *
 * Header fields are also bound into the AAD of [BackupFile.pwWrap], so an edited header fails like
 * a wrong passphrase; edited or missing entries fail the MAC; a truncated file fails to parse.
 */
object BackupCodec {
    const val FILE_VERSION: Byte = 0x01
    val MAGIC = byteArrayOf('P'.code.toByte(), 'V'.code.toByte(), 'A'.code.toByte(), 'U'.code.toByte(), 'L'.code.toByte(), 'T'.code.toByte(), 0x00, FILE_VERSION)
    val MAC_INFO = "pv1 export".toByteArray(Charsets.US_ASCII)

    /** Bounds for a file we did not write. Generous for a personal vault, small enough to never OOM. */
    const val MAX_FILE_BYTES = 64 * 1024 * 1024
    const val MAX_ENTRIES = 100_000
    const val MAX_BLOB_BYTES = 1024 * 1024
    private const val MAX_ID_BYTES = 64

    /** The caller wipes the result. */
    fun macKey(vaultKey: ByteArray): ByteArray = Hkdf.sha256(vaultKey, null, MAC_INFO, Hkdf.HASH_BYTES)

    fun encode(
        header: VaultHeader,
        pwWrap: ByteArray,
        entries: List<BackupEntry>,
        exportedAt: Long,
        macKey: ByteArray,
    ): ByteArray {
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { out ->
            out.write(MAGIC)
            require(header.vaultId.size == KeyHierarchy.VAULT_ID_BYTES)
            out.write(header.vaultId)
            out.writeInt(header.formatVersion)
            shortBytes(out, header.kdfAlgorithm.toByteArray(Charsets.US_ASCII))
            out.writeInt(header.kdfMemoryKib)
            out.writeInt(header.kdfIterations)
            out.writeInt(header.kdfParallelism)
            shortBytes(out, header.kdfSalt)
            require(pwWrap.size <= 0xFFFF)
            out.writeShort(pwWrap.size)
            out.write(pwWrap)
            out.writeLong(header.createdAt)
            out.writeLong(exportedAt)
            require(entries.size <= MAX_ENTRIES)
            out.writeInt(entries.size)
            for (e in entries) {
                shortBytes(out, e.id.toByteArray(Charsets.US_ASCII))
                out.writeInt(e.formatVersion)
                require(e.summaryBlob.size <= MAX_BLOB_BYTES && e.secretBlob.size <= MAX_BLOB_BYTES)
                out.writeInt(e.summaryBlob.size)
                out.write(e.summaryBlob)
                out.writeInt(e.secretBlob.size)
                out.write(e.secretBlob)
            }
        }
        val body = buffer.toByteArray()
        return body + Hkdf.hmac(macKey, body)
    }

    /**
     * Structure only: no key needed. Rejects anything incomplete, oversized, or with trailing
     * bytes. The MAC is checked later by [verify].
     */
    fun parse(bytes: ByteArray): BackupFile {
        if (bytes.size > MAX_FILE_BYTES) throw BackupFormatException("Too large")
        if (bytes.size < MAGIC.size + Hkdf.HASH_BYTES) throw BackupFormatException("Not a backup")
        val r = Reader(bytes, bytes.size - Hkdf.HASH_BYTES)
        val magic = r.bytes(MAGIC.size)
        if (!magic.copyOf(MAGIC.size - 1).contentEquals(MAGIC.copyOf(MAGIC.size - 1))) {
            throw BackupFormatException("Not a backup")
        }
        if (magic.last() != FILE_VERSION) throw BackupFormatException("Unsupported version")
        val vaultId = r.bytes(KeyHierarchy.VAULT_ID_BYTES)
        val formatVersion = r.int()
        val kdfAlgorithm = r.ascii(r.u8())
        val memory = r.int()
        val iterations = r.int()
        val parallelism = r.int()
        val salt = r.bytes(r.u8())
        val pwWrap = r.bytes(r.u16())
        val vaultCreatedAt = r.long()
        val exportedAt = r.long()
        val count = r.int()
        if (count !in 0..MAX_ENTRIES) throw BackupFormatException("Bad entry count")
        val entries = ArrayList<BackupEntry>(minOf(count, 1024))
        val ids = HashSet<String>()
        repeat(count) {
            val idLength = r.u8()
            if (idLength !in 1..MAX_ID_BYTES) throw BackupFormatException("Bad entry")
            val id = r.ascii(idLength)
            if (!ids.add(id)) throw BackupFormatException("Duplicate entry")
            val version = r.int()
            val summary = r.bytes(r.blobLength())
            val secret = r.bytes(r.blobLength())
            entries += BackupEntry(id, version, summary, secret)
        }
        if (!r.atEnd) throw BackupFormatException("Trailing bytes")
        return BackupFile(
            vaultId, formatVersion, kdfAlgorithm, salt, memory, iterations, parallelism, pwWrap,
            vaultCreatedAt, exportedAt, entries, bytes.copyOf(),
        )
    }

    /** True when the whole-file MAC matches under the vault key's export MAC key. */
    fun verify(file: BackupFile, macKey: ByteArray): Boolean = file.macMatches(macKey)

    private fun shortBytes(out: DataOutputStream, b: ByteArray) {
        require(b.size <= 0xFF)
        out.writeByte(b.size)
        out.write(b)
    }

    /** Bounds-checked reader over `bytes[0, limit)`. Running past [limit] means truncated. */
    private class Reader(private val b: ByteArray, private val limit: Int) {
        private var pos = 0
        val atEnd: Boolean get() = pos == limit

        private fun need(n: Int) {
            if (n < 0 || limit < 0 || n > limit - pos) throw BackupFormatException("Incomplete")
        }

        fun bytes(n: Int): ByteArray {
            need(n)
            return b.copyOfRange(pos, pos + n).also { pos += n }
        }

        fun u8(): Int {
            need(1)
            return b[pos++].toInt() and 0xFF
        }

        fun u16(): Int = (u8() shl 8) or u8()

        fun int(): Int {
            need(4)
            var v = 0
            repeat(4) { v = (v shl 8) or (b[pos++].toInt() and 0xFF) }
            return v
        }

        fun long(): Long {
            need(8)
            var v = 0L
            repeat(8) { v = (v shl 8) or (b[pos++].toLong() and 0xFF) }
            return v
        }

        fun blobLength(): Int {
            val n = int()
            if (n !in 0..MAX_BLOB_BYTES) throw BackupFormatException("Bad blob")
            return n
        }

        fun ascii(n: Int): String {
            val raw = bytes(n)
            if (raw.any { it < 0x20 || it > 0x7E }) throw BackupFormatException("Bad text")
            return String(raw, Charsets.US_ASCII)
        }
    }
}
