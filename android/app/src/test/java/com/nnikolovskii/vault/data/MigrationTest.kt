package com.nnikolovskii.vault.data

import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Runs [VaultMigrations] on databases built from the frozen v1 / v2 schema JSON and checks that
 * the result matches the next exported schema column for column, with the old rows intact. (The
 * real Room validation runs on the phone; this catches a migration that would fail it.)
 */
class MigrationTest {
    private val schemas = File("schemas/com.nnikolovskii.vault.data.VaultDatabase")

    private fun json(version: Int) = File(schemas, "$version.json").readText()

    private fun createSql(json: String): Map<String, String> =
        Regex("\"tableName\": \"(\\w+)\",\\s*\"createSql\": \"(.*?)\",").findAll(json)
            .associate { it.groupValues[1] to it.groupValues[2].replace("\${TABLE_NAME}", it.groupValues[1]) }

    private fun open(version: Int): Connection =
        DriverManager.getConnection("jdbc:sqlite::memory:").also { c ->
            c.createStatement().use { s -> createSql(json(version)).values.forEach(s::execute) }
        }

    /** name|type|notnull|default|pk for every column, in order. */
    private fun columns(c: Connection, table: String): List<String> =
        c.createStatement().use { s ->
            s.executeQuery("PRAGMA table_info(`$table`)").use { r ->
                buildList {
                    while (r.next()) {
                        add("${r.getString("name")}|${r.getString("type")}|${r.getInt("notnull")}|${r.getString("dflt_value")}|${r.getInt("pk")}")
                    }
                }
            }
        }

    private fun assertMatchesSchema(version: Int, migrated: Connection) {
        val expected = open(version)
        val tables = createSql(json(version)).keys
        assertEquals(setOf("vault_meta", "entries"), tables)
        for (t in tables) assertEquals(t, columns(expected, t), columns(migrated, t))
    }

    private fun insertV1Meta(c: Connection, vaultId: ByteArray) {
        c.prepareStatement(
            "INSERT INTO vault_meta VALUES (1, ?, 1, 'argon2id-v19', ?, 65536, 4, 1, ?, 'pv.device.v1', 42)",
        ).use { p ->
            p.setBytes(1, vaultId)
            p.setBytes(2, ByteArray(16))
            p.setBytes(3, ByteArray(90))
            p.executeUpdate()
        }
    }

    private fun insertEntry(c: Connection, secretBytes: Int = 93) {
        c.prepareStatement("INSERT INTO entries VALUES ('id-1', 1, ?, ?)").use { p ->
            p.setBytes(1, ByteArray(93))
            p.setBytes(2, ByteArray(secretBytes))
            p.executeUpdate()
        }
    }

    @Test
    fun v1IsStillTheFrozenSchema() {
        assertTrue(json(1).contains("\"identityHash\": \"aedb7116e59010e7e007ad3ef57bc915\""))
    }

    @Test
    fun v2IsStillTheFrozenSchema() {
        assertTrue(json(2).contains("\"identityHash\": \"a1ec7b37e553c0e13e0d5b1373f2d288\""))
    }

    @Test
    fun migrationsCoverEveryExportedVersion() {
        val versions = schemas.listFiles()!!.mapNotNull { it.name.removeSuffix(".json").toIntOrNull() }.sorted()
        assertEquals((1..3).toList(), versions)
        val steps = VaultMigrations.ALL.map { it.startVersion to it.endVersion }
        assertEquals((1 until versions.last()).map { it to it + 1 }, steps)
    }

    @Test
    fun v1ToV2MatchesTheExportedV2SchemaAndKeepsRows() {
        val migrated = open(1)
        val vaultId = ByteArray(16) { it.toByte() }
        insertV1Meta(migrated, vaultId)
        insertEntry(migrated)

        migrated.createStatement().use { s -> VaultMigrations.SQL_1_2.forEach(s::execute) }
        assertMatchesSchema(2, migrated)

        migrated.createStatement().use { s ->
            s.executeQuery("SELECT vaultId, kdfIterations, backupInfo FROM vault_meta").use { r ->
                assertTrue(r.next())
                assertArrayEquals(vaultId, r.getBytes(1))
                assertEquals(4, r.getInt(2))
                assertNull(r.getBytes(3))
            }
            s.executeQuery("SELECT COUNT(*) FROM entries").use { r ->
                r.next()
                assertEquals(1, r.getInt(1))
            }
        }
    }

    @Test
    fun v2ToV3MatchesTheExportedV3SchemaAndKeepsRows() {
        val db = open(2)
        val vaultId = ByteArray(16) { (it * 3).toByte() }
        val backupInfo = ByteArray(39) { 7 }
        db.prepareStatement(
            "INSERT INTO vault_meta VALUES (1, ?, 1, 'argon2id-v19', ?, 65536, 5, 1, ?, 'pv.device.v1', 42, ?)",
        ).use { p ->
            p.setBytes(1, vaultId)
            p.setBytes(2, ByteArray(16))
            p.setBytes(3, ByteArray(90))
            p.setBytes(4, backupInfo)
            p.executeUpdate()
        }
        insertEntry(db, secretBytes = 157)

        db.createStatement().use { s -> VaultMigrations.SQL_2_3.forEach(s::execute) }
        assertMatchesSchema(3, db)

        db.createStatement().use { s ->
            s.executeQuery("SELECT vaultId, kdfIterations, backupInfo, biometricWrap, passphraseInfo, settings FROM vault_meta").use { r ->
                assertTrue(r.next())
                assertArrayEquals(vaultId, r.getBytes(1))
                assertEquals(5, r.getInt(2))
                assertArrayEquals(backupInfo, r.getBytes(3))
                // Biometric off, passphrase due, default settings.
                assertNull(r.getBytes(4))
                assertNull(r.getBytes(5))
                assertNull(r.getBytes(6))
            }
            s.executeQuery("SELECT LENGTH(secretBlob) FROM entries WHERE id = 'id-1'").use { r ->
                assertTrue(r.next())
                assertEquals(157, r.getInt(1))
            }
        }
    }

    @Test
    fun v1ThroughV2ToV3ChainsCleanly() {
        val db = open(1)
        insertV1Meta(db, ByteArray(16))
        insertEntry(db)
        db.createStatement().use { s ->
            VaultMigrations.SQL_1_2.forEach(s::execute)
            VaultMigrations.SQL_2_3.forEach(s::execute)
        }
        assertMatchesSchema(3, db)
        db.createStatement().use { s ->
            s.executeQuery("SELECT COUNT(*), backupInfo, settings FROM vault_meta").use { r ->
                assertTrue(r.next())
                assertEquals(1, r.getInt(1))
                assertNull(r.getBytes(2))
                assertNull(r.getBytes(3))
            }
            s.executeQuery("SELECT COUNT(*) FROM entries").use { r ->
                r.next()
                assertEquals(1, r.getInt(1))
            }
        }
    }
}
