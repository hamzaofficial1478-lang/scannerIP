package io.github.scannerip.core

import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class IdentityTest {
    private val fp = "android-id-123|Google|Pixel 8|shiba".toByteArray()
    private fun secret() = ByteArray(32).also(SecureRandom()::nextBytes)

    @Test
    fun hkdfMatchesRfc5869TestCase1() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = ByteArray(13) { it.toByte() }
        val info = ByteArray(10) { (0xf0 + it).toByte() }
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            Hkdf.derive(ikm, salt, info, 42).toHex(),
        )
    }

    @Test
    fun rootIdIsStableButDependsOnTheKey() {
        val s = secret()
        val a = IdentityVault(SoftwareKeys(s), fp)
        val b = IdentityVault(SoftwareKeys(s), fp)
        val c = IdentityVault(SoftwareKeys(secret()), fp)
        assertEquals(a.rootId, b.rootId)
        assertNotEquals(a.rootId, c.rootId)
        assertNotEquals(a.sessionId, b.sessionId) // new session every launch
    }

    @Test
    fun rotatingIdChangesEveryShift() {
        val vault = IdentityVault(SoftwareKeys(secret()), fp)
        val snaps = (1..5).map { vault.rotate("203.0.113.5") }
        assertEquals(5, snaps.map { it.rotatingId }.toSet().size)
        assertEquals(5, snaps.map { it.sealed }.toSet().size) // fresh nonce each time
        assertEquals(listOf(1, 2, 3, 4, 5), snaps.map { it.rotation })
        assertEquals(snaps.last(), vault.current)
        assertTrue(snaps.all { it.rotatingId.matches(Regex("RID(-[0-9A-F]{4}){4}")) })
    }

    @Test
    fun sealRoundTripAndWrongKey() {
        val s = secret()
        val vault = IdentityVault(SoftwareKeys(s), fp)
        val token = vault.seal()
        assertContentEquals(fp, vault.unseal(token))
        assertContentEquals(fp, IdentityVault(SoftwareKeys(s), fp).unseal(token)) // same phone, same key
        assertFailsWith<AEADBadTagException> { IdentityVault(SoftwareKeys(secret()), fp).unseal(token) }
    }

    @Test
    fun verifySealOnlyWorksOnTheSamePhone() {
        val s = secret()
        val vault = IdentityVault(SoftwareKeys(s), fp)
        val token = vault.rotate("192.0.2.9").sealed
        assertTrue(vault.verifySeal(token))
        assertFalse(IdentityVault(SoftwareKeys(secret()), fp).verifySeal(token)) // another phone's key
        assertFalse(IdentityVault(SoftwareKeys(s), "other device".toByteArray()).verifySeal(token))
        assertFalse(vault.verifySeal("not-a-token"))
    }

    @Test
    fun tamperedSealIsRejected() {
        val vault = IdentityVault(SoftwareKeys(secret()), fp)
        val raw = java.util.Base64.getUrlDecoder().decode(vault.seal())
        raw[raw.size - 1] = (raw.last().toInt() xor 1).toByte()
        assertFailsWith<AEADBadTagException> { vault.unseal(java.util.Base64.getUrlEncoder().encodeToString(raw)) }
    }

    @Test
    fun rawFingerprintNeverShowsUp() {
        val vault = IdentityVault(SoftwareKeys(secret()), fp)
        vault.rotate("198.51.100.1")
        val shown = vault.toString() + vault.layers().toString() + vault.current.toString()
        for (piece in listOf("android-id-123", "Pixel 8", "shiba", String(fp))) assertFalse(piece in shown)
    }

    @Test
    fun layersHasFiveRows() {
        val vault = IdentityVault(SoftwareKeys(secret()), fp)
        val rows = vault.layers()
        assertEquals(5, rows.size)
        assertTrue("waiting" in rows[4].value)
        vault.rotate("192.0.2.1")
        assertTrue(vault.layers()[4].value.startsWith("RID-"))
    }

    @Test
    fun shortSecretRejected() {
        assertFailsWith<IllegalArgumentException> { SoftwareKeys(ByteArray(4)) }
    }
}
