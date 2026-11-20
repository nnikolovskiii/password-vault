package com.nnikolovskii.vault.crypto

/** The device-bound key is gone, invalidated, or no longer opens the stored wrap. */
class DeviceKeyLostException(message: String = "Device key unavailable") : Exception(message)

/** The device key exists but refuses to work right now (phone locked). Try again later. */
class DeviceLockedException(message: String = "Phone is locked") : Exception(message)

/**
 * Hardware-bound second wrap of `pwWrap`. On the phone this is [KeystoreDeviceWrap]; the JVM
 * tests use an in-memory fake.
 */
interface DeviceWrap {
    val alias: String

    /** Creates the key, replacing a stale one with the same alias. */
    fun createKey()

    fun hasKey(): Boolean

    fun wrap(plaintext: ByteArray, aad: ByteArray): ByteArray

    /**
     * @throws DeviceKeyLostException when the key is missing, invalidated, or the blob does not open.
     * @throws DeviceLockedException when the phone is locked (transient).
     */
    fun unwrap(blob: ByteArray, aad: ByteArray): ByteArray
}
