package com.nnikolovskii.vault.domain

/**
 * Associated data for every AEAD in the vault. Binding vault id, entry id, field, and the KDF
 * header into the AAD makes moved, swapped, or downgraded blobs fail to decrypt.
 */
object Aad {
    enum class Field(val label: String) { Summary("summary"), Secret("secret") }

    /** `pv1|<vaultId>|argon2id|v19|m|t|p|<salt>` (hex, fixed order). */
    fun header(
        formatVersion: Int,
        vaultId: ByteArray,
        kdfAlgorithm: String,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int,
        salt: ByteArray,
    ): ByteArray = buildString {
        append("pv").append(formatVersion).append('|')
        append(vaultId.toHex()).append('|')
        append(kdfAlgorithm.replace('-', '|')).append('|')
        append(memoryKib).append('|')
        append(iterations).append('|')
        append(parallelism).append('|')
        append(salt.toHex())
    }.toByteArray(Charsets.UTF_8)

    /** `pv1|<vaultId>|<entryId>|summary` or `…|secret`. */
    fun entry(vaultId: ByteArray, entryId: String, field: Field): ByteArray =
        "pv1|${vaultId.toHex()}|$entryId|${field.label}".toByteArray(Charsets.UTF_8)

    /**
     * `pv1|<vaultId>|vault|backup` for the encrypted backup info in `vault_meta`. Entry ids are
     * UUIDs, so this can never equal an entry's AAD.
     */
    fun backupInfo(vaultId: ByteArray): ByteArray = vault(vaultId, "backup")

    /** `pv1|<vaultId>|vault|settings`: user settings, AEAD under the VK. */
    fun settings(vaultId: ByteArray): ByteArray = vault(vaultId, "settings")

    /** `pv1|<vaultId>|vault|biometric`: the VK wrapped by the biometric Keystore key. */
    fun biometric(vaultId: ByteArray): ByteArray = vault(vaultId, "biometric")

    /** `pv1|<vaultId>|vault|passphrase`: last passphrase time, wrapped by the device key. */
    fun passphraseInfo(vaultId: ByteArray): ByteArray = vault(vaultId, "passphrase")

    private fun vault(vaultId: ByteArray, name: String): ByteArray =
        "pv1|${vaultId.toHex()}|vault|$name".toByteArray(Charsets.UTF_8)
}

private val HEX = "0123456789abcdef".toCharArray()

fun ByteArray.toHex(): String {
    val out = CharArray(size * 2)
    for (i in indices) {
        val v = this[i].toInt() and 0xFF
        out[i * 2] = HEX[v ushr 4]
        out[i * 2 + 1] = HEX[v and 0x0F]
    }
    return String(out)
}
