package io.github.scannerip.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/*
 * The phone's version of "git pull".
 *
 * A phone can't run the source code in the repo, only a finished app (APK).
 * GitHub builds one every time main changes and publishes two files next to
 * each other: ScannerIP.apk and a small version.json describing it. The app
 * reads version.json, and if the build is newer than itself it downloads the
 * APK, checks its SHA-256 fingerprint matches, and hands it to Android to
 * install over the top.
 */

@Serializable
data class UpdateInfo(
    val versionCode: Int,
    val versionName: String,
    /** SHA-256 of the APK, as 64 hex characters. */
    val sha256: String,
    val notes: String = "",
    val commit: String = "",
)

class UpdateError(message: String, cause: Throwable? = null) : IOException(message, cause)

object Updates {
    private val json = Json { ignoreUnknownKeys = true }
    private val SHA256 = Regex("[0-9a-f]{64}")

    fun parse(text: String): UpdateInfo {
        val info = try {
            json.decodeFromString<UpdateInfo>(text)
        } catch (e: Exception) {
            throw UpdateError("The update description from GitHub didn't make sense.", e)
        }
        if (info.versionCode <= 0 || !SHA256.matches(info.sha256.lowercase())) {
            throw UpdateError("The update description from GitHub is missing its version or fingerprint.")
        }
        return info.copy(sha256 = info.sha256.lowercase())
    }

    fun encode(info: UpdateInfo): String = json.encodeToString(UpdateInfo.serializer(), info)

    /** Download and read version.json. */
    fun fetchInfo(client: OkHttpClient, url: String): UpdateInfo =
        client.newCall(Request.Builder().url(url).header("Cache-Control", "no-cache").build()).execute().use { response ->
            if (!response.isSuccessful) throw UpdateError("GitHub answered ${response.code} when asked for updates.")
            parse(response.body!!.string())
        }

    fun isNewer(info: UpdateInfo, installedVersionCode: Int) = info.versionCode > installedVersionCode

    /**
     * Stream the APK to [dest], working out its SHA-256 on the way. If it
     * doesn't match [expectedSha256] the file is deleted and this throws, so a
     * damaged or swapped download can never reach the installer.
     */
    fun download(
        client: OkHttpClient,
        url: String,
        dest: File,
        expectedSha256: String,
        onProgress: (done: Long, total: Long) -> Unit = { _, _ -> },
    ): File {
        dest.parentFile?.mkdirs()
        val digest = MessageDigest.getInstance("SHA-256")
        try {
            client.newCall(Request.Builder().url(url).build()).execute().use { response ->
                if (!response.isSuccessful) throw UpdateError("GitHub answered ${response.code} when downloading the update.")
                val body = response.body!!
                val total = body.contentLength()
                var done = 0L
                body.byteStream().use { input ->
                    dest.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024)
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            digest.update(buffer, 0, read)
                            output.write(buffer, 0, read)
                            done += read
                            onProgress(done, total)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            dest.delete()
            throw if (e is UpdateError) e else UpdateError("The download stopped: ${e.message}", e)
        }
        val actual = digest.digest().toHex()
        if (actual != expectedSha256.lowercase()) {
            dest.delete()
            throw UpdateError("The downloaded file's fingerprint doesn't match, so it was thrown away.")
        }
        return dest
    }
}
