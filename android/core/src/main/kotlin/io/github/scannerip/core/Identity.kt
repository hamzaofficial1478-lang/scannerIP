package io.github.scannerip.core

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/*
 * Layered device identity that changes every time the IP changes.
 *
 * The idea is that your real device ID never leaves this app. Everything anyone
 * else could ever see is derived from it in a one-way fashion, and the outermost
 * layer is re-derived on every IP shift so two scans can't be linked together
 * just by looking at the IDs.
 *
 *   Layer 0  Hardware ID        Android ID + maker + model. In memory only.
 *   Layer 1  Sealed copy        Layer 0 encrypted with AES-256-GCM. A fresh
 *                               nonce every shift, so the ciphertext looks
 *                               different every time. On a phone the key sits
 *                               in the Android Keystore and can't be copied out.
 *   Layer 2  Anonymous root ID  HMAC-SHA256(device key, Layer 0). One-way.
 *   Layer 3  Session ID         HMAC(root, random nonce). New every launch.
 *   Layer 4  Rotating ID        HMAC(session, shift number + exit IP).
 *                               New on every IP shift.
 *
 * HMAC is RFC 2104, HKDF is RFC 5869 and AES-GCM is NIST SP 800-38D.
 */

/** The two keys the layers need. On Android they live in the Keystore. */
interface DeviceKeys {
    /** Where the keys live, for the UI. */
    val description: String

    /** HMAC-SHA256 with a key that never leaves this device. */
    fun rootMac(data: ByteArray): ByteArray

    /** AES-256-GCM encrypt. Returns nonce || ciphertext+tag. */
    fun seal(plain: ByteArray, aad: ByteArray): ByteArray

    /** Opposite of [seal]. Throws if the key is wrong or the data was changed. */
    fun unseal(blob: ByteArray, aad: ByteArray): ByteArray
}

/** Keys derived from a random secret held in memory - used by the tests. */
class SoftwareKeys(secret: ByteArray, private val random: SecureRandom = SecureRandom()) : DeviceKeys {
    init {
        require(secret.size >= 16) { "secret must be at least 16 bytes" }
    }

    private val sealKey = Hkdf.derive(secret, info = "scannerip/seal-key/v1".toByteArray())
    private val rootKey = Hkdf.derive(secret, info = "scannerip/root-key/v1".toByteArray())

    override val description = "software key"

    override fun rootMac(data: ByteArray): ByteArray = hmacSha256(rootKey, data)

    override fun seal(plain: ByteArray, aad: ByteArray): ByteArray {
        val nonce = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sealKey, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return nonce + cipher.doFinal(plain)
    }

    override fun unseal(blob: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sealKey, "AES"), GCMParameterSpec(128, blob, 0, 12))
        cipher.updateAAD(aad)
        return cipher.doFinal(blob, 12, blob.size - 12)
    }
}

/** RFC 5869 HKDF with SHA-256. */
object Hkdf {
    fun derive(ikm: ByteArray, salt: ByteArray? = null, info: ByteArray = ByteArray(0), length: Int = 32): ByteArray {
        require(length <= 255 * 32)
        val prk = hmacSha256(salt?.takeIf { it.isNotEmpty() } ?: ByteArray(32), ikm)
        val out = java.io.ByteArrayOutputStream()
        var block = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            block = hmacSha256(prk, block + info + byteArrayOf(counter.toByte()))
            out.write(block)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }
}

fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(data)
    }

fun formatId(prefix: String, digest: ByteArray, groups: Int = 4): String =
    digest.copyOf(groups * 2).toHex().uppercase().chunked(4).joinToString("-", prefix = "$prefix-")

data class IdentitySnapshot(
    val rotation: Int,
    val exitIp: String,
    val rotatingId: String,
    val sealed: String,
    val sessionId: String,
    val rootId: String,
    val at: Long,
)

data class Layer(val name: String, val value: String, val why: String)

/** Holds Layer 0 and hands out the derived layers. */
class IdentityVault(
    private val keys: DeviceKeys,
    fingerprint: ByteArray,
    random: SecureRandom = SecureRandom(),
) {
    private val fingerprint = fingerprint.copyOf()
    private val sessionKey: ByteArray
    val rootId: String
    val sessionId: String

    @Volatile
    var rotation = 0
        private set

    @Volatile
    var current: IdentitySnapshot? = null
        private set

    init {
        val root = keys.rootMac(this.fingerprint)
        rootId = formatId("ROOT", root)
        sessionKey = hmacSha256(root, ByteArray(16).also(random::nextBytes))
        sessionId = formatId("SID", sessionKey)
    }

    val fingerprintSize: Int get() = fingerprint.size
    val keyDescription: String get() = keys.description

    // Keep Layer 0 out of logs and crash reports.
    override fun toString() = "IdentityVault($rootId, rotation=$rotation)"

    /** Layer 1: encrypt Layer 0. A new nonce every call means new ciphertext. */
    fun seal(): String = Base64.getUrlEncoder().encodeToString(keys.seal(fingerprint, AAD))

    /** Open a Layer 1 token. Throws with the wrong key or a tampered token. */
    fun unseal(token: String): ByteArray = keys.unseal(Base64.getUrlDecoder().decode(token), AAD)

    /** True if [token] opens with this phone's key and holds exactly this phone's Layer 0. */
    fun verifySeal(token: String): Boolean = try {
        unseal(token).contentEquals(fingerprint)
    } catch (_: Exception) {
        false
    }

    /** Layer 4: derive a brand new ID for this shift and exit IP. */
    @Synchronized
    fun rotate(exitIp: String): IdentitySnapshot {
        rotation += 1
        val message = "$rotation|$exitIp|${System.nanoTime()}".toByteArray()
        val snapshot = IdentitySnapshot(
            rotation = rotation,
            exitIp = exitIp,
            rotatingId = formatId("RID", hmacSha256(sessionKey, message)),
            sealed = seal(),
            sessionId = sessionId,
            rootId = rootId,
            at = System.currentTimeMillis(),
        )
        current = snapshot
        return snapshot
    }

    /** Rows for the UI. Layer 0 is never included, only its size. */
    fun layers(): List<Layer> {
        val cur = current
        val sealed = cur?.sealed ?: seal()
        return listOf(
            Layer("Layer 0  Hardware ID", "●".repeat(12) + "  ($fingerprintSize bytes)",
                "Never shown, saved or sent anywhere."),
            Layer("Layer 1  Sealed (AES-256-GCM)", sealed.take(28) + "...",
                "Encrypted copy. Only the key in this phone ($keyDescription) can open it."),
            Layer("Layer 2  Anonymous root", rootId, "One-way HMAC of Layer 0. Can't be reversed."),
            Layer("Layer 3  Session", sessionId, "New every time the app starts."),
            Layer("Layer 4  Rotating ID", cur?.rotatingId ?: "(waiting for first shift)", "Changes with every IP shift."),
        )
    }

    companion object {
        val AAD = "scannerip/layer1/v1".toByteArray()
    }
}
