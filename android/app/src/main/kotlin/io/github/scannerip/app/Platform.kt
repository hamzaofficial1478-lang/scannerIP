package io.github.scannerip.app

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import io.github.scannerip.core.DeviceKeys
import io.github.scannerip.core.SoftwareKeys
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The two keys behind the ID layers, generated inside the Android Keystore.
 * They can be used by this app but never read out, not even by us, so the
 * sealed Layer 1 copy really can only be opened on this phone. On most phones
 * the Keystore is backed by secure hardware (a TEE or StrongBox chip).
 */
class AndroidKeystoreKeys : DeviceKeys {
    private val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private val sealKey: SecretKey = existing(SEAL_ALIAS) ?: KeyGenerator
        .getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        .apply {
            init(KeyGenParameterSpec.Builder(SEAL_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build())
        }.generateKey()

    private val rootKey: SecretKey = existing(ROOT_ALIAS) ?: KeyGenerator
        .getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER)
        .apply { init(KeyGenParameterSpec.Builder(ROOT_ALIAS, KeyProperties.PURPOSE_SIGN).build()) }
        .generateKey()

    override val description: String = if (isHardwareBacked(sealKey)) "Android Keystore, secure hardware" else "Android Keystore"

    private fun existing(alias: String): SecretKey? = keyStore.getKey(alias, null) as? SecretKey

    override fun rootMac(data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(rootKey)
        doFinal(data)
    }

    override fun seal(plain: ByteArray, aad: ByteArray): ByteArray {
        // The Keystore insists on choosing the nonce itself, which is what we want anyway.
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, sealKey)
        cipher.updateAAD(aad)
        val encrypted = cipher.doFinal(plain)
        return cipher.iv + encrypted
    }

    override fun unseal(blob: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, sealKey, GCMParameterSpec(128, blob, 0, 12))
        cipher.updateAAD(aad)
        return cipher.doFinal(blob, 12, blob.size - 12)
    }

    private fun isHardwareBacked(key: SecretKey): Boolean = try {
        val info = SecretKeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= 31) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    } catch (_: Exception) {
        false
    }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val SEAL_ALIAS = "scannerip.layer1.seal"
        private const val ROOT_ALIAS = "scannerip.layer2.root"
    }
}

/** Keystore keys if the phone has a working Keystore, otherwise a private key file. */
fun deviceKeys(context: Context): DeviceKeys = try {
    AndroidKeystoreKeys()
} catch (_: Exception) {
    val file = File(context.noBackupFilesDir, "secret.key")
    val secret = file.takeIf { it.length() == 32L }?.readBytes()
        ?: ByteArray(32).also(SecureRandom()::nextBytes).also(file::writeBytes)
    SoftwareKeys(secret)
}

/**
 * Layer 0. ANDROID_ID is unique to this app on this phone (and this user), so
 * it can't be used to follow you between apps even if it did leak. It never
 * leaves memory either way.
 */
@SuppressLint("HardwareIds")
fun deviceFingerprint(context: Context): ByteArray {
    val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
    return listOf(androidId, Build.MANUFACTURER, Build.MODEL, Build.DEVICE, Build.BOARD)
        .joinToString("|").toByteArray()
}
