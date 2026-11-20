package com.nnikolovskii.vault.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class VaultSettingsTest {
    @Test
    fun defaultsAreThePart1Constants() {
        val d = VaultSettings()
        assertEquals(60, d.backgroundLockSeconds)
        assertEquals(300, d.idleLockSeconds)
        assertEquals(30, d.clipboardClearSeconds)
        assertEquals(AutoLockPolicy.BACKGROUND_MILLIS, d.backgroundLockMillis)
        assertEquals(AutoLockPolicy.IDLE_MILLIS, d.idleLockMillis)
        assertEquals(ClipboardPolicy.CLEAR_AFTER_MILLIS, d.clipboardClearMillis)
        // Every default is one of its own choices.
        assert(d.backgroundLockSeconds in VaultSettings.BACKGROUND_CHOICES)
        assert(d.idleLockSeconds in VaultSettings.IDLE_CHOICES)
        assert(d.clipboardClearSeconds in VaultSettings.CLIPBOARD_CHOICES)
    }

    @Test
    fun noChoiceMeansNever() {
        val all = VaultSettings.BACKGROUND_CHOICES + VaultSettings.IDLE_CHOICES + VaultSettings.CLIPBOARD_CHOICES
        assert(all.all { it in 1..900 })
    }

    @Test
    fun roundTrip() {
        val s = VaultSettings(
            backgroundLockSeconds = 15,
            idleLockSeconds = 900,
            clipboardClearSeconds = 120,
            generator = GeneratorOptions(
                mode = GeneratorOptions.Mode.Words, length = 33, lower = true, upper = false,
                digits = true, symbols = false, words = 8, separator = ' ', capitalize = true, addDigit = true,
            ),
        )
        assertEquals(s, SettingsCodec.decode(SettingsCodec.encode(s)))
        assertEquals(VaultSettings.DEFAULT, SettingsCodec.decode(SettingsCodec.encode(VaultSettings.DEFAULT)))
    }

    @Test
    fun valuesOutsideTheChoicesFallBackToDefaults() {
        val forged = EntryCodec.assemble(
            listOf(
                1 to EntryCodec.varint(86_400), // background: one day
                2 to EntryCodec.varint(0), // idle: never
                3 to EntryCodec.varint(15), // clipboard: valid
                17 to EntryCodec.varint(5_000), // generator length
                16 to EntryCodec.varint(9), // unknown mode
            ),
        )
        val s = SettingsCodec.decode(forged)
        assertEquals(60, s.backgroundLockSeconds)
        assertEquals(300, s.idleLockSeconds)
        assertEquals(15, s.clipboardClearSeconds)
        assertEquals(GeneratorOptions.MAX_LENGTH, s.generator.length)
        assertEquals(GeneratorOptions.Mode.Characters, s.generator.mode)
    }

    @Test
    fun unknownTagsFromALaterVersionAreSkipped() {
        val later = SettingsCodec.encode(VaultSettings(idleLockSeconds = 600)) +
            byteArrayOf(40, 3, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte())
        assertEquals(600, SettingsCodec.decode(later).idleLockSeconds)
    }

    @Test
    fun aMissingFieldKeepsItsDefault() {
        val partial = EntryCodec.assemble(listOf(3 to EntryCodec.varint(10)))
        val s = SettingsCodec.decode(partial)
        assertEquals(10, s.clipboardClearSeconds)
        assertEquals(60, s.backgroundLockSeconds)
        assertEquals(GeneratorOptions(), s.generator)
    }

    @Test
    fun notASettingsPayloadThrows() {
        for (bad in listOf(ByteArray(0), byteArrayOf(2, 1, 1, 60), byteArrayOf(1, 1, 5, 60))) {
            try {
                SettingsCodec.decode(bad)
                fail()
            } catch (_: CodecException) {
            }
        }
    }
}
