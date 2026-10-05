package io.github.scannerip.core

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okio.Buffer
import java.io.File
import java.net.InetSocketAddress
import java.security.MessageDigest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UpdateTest {
    private lateinit var web: MockWebServer
    private val apk = ByteArray(300_000) { (it * 31 % 251).toByte() }
    private val apkSha = MessageDigest.getInstance("SHA-256").digest(apk).toHex()
    private fun versionJson(code: Int = 12, sha: String = apkSha) =
        """{"versionCode": $code, "versionName": "1.0.$code", "sha256": "$sha", "notes": "Faster scanning", "extra": 1}"""

    @BeforeTest
    fun setUp() {
        web = MockWebServer()
        // Like GitHub: release downloads redirect to a separate file server.
        web.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when (request.path) {
                "/releases/download/latest/version.json" -> MockResponse().setResponseCode(302).addHeader("Location", "/files/version.json")
                "/files/version.json" -> MockResponse().setBody(versionJson())
                "/releases/download/latest/ScannerIP.apk" -> MockResponse().setResponseCode(302).addHeader("Location", "/files/app.apk")
                "/files/app.apk" -> MockResponse().setBody(Buffer().write(apk))
                else -> MockResponse().setResponseCode(404)
            }
        }
        web.start()
    }

    @AfterTest
    fun tearDown() = web.shutdown()

    private fun direct() = Net.client(null, followRedirects = true)

    @Test
    fun readsVersionJsonThroughGithubsRedirect() {
        val info = Updates.fetchInfo(direct(), web.url("/releases/download/latest/version.json").toString())
        assertEquals(UpdateInfo(12, "1.0.12", apkSha, "Faster scanning"), info)
        assertTrue(Updates.isNewer(info, installedVersionCode = 11))
        assertFalse(Updates.isNewer(info, installedVersionCode = 12))
    }

    @Test
    fun rejectsNonsense() {
        assertFailsWith<UpdateError> { Updates.parse("<html>not json</html>") }
        assertFailsWith<UpdateError> { Updates.parse(versionJson(sha = "abc")) }
        assertFailsWith<UpdateError> { Updates.parse(versionJson(code = 0)) }
        assertEquals(apkSha, Updates.parse(versionJson(sha = apkSha.uppercase())).sha256)
        val info = Updates.parse(versionJson())
        assertEquals(info, Updates.parse(Updates.encode(info)))
        val missing = web.url("/nothing/version.json").toString()
        assertFailsWith<UpdateError> { Updates.fetchInfo(direct(), missing) }
    }

    @Test
    fun downloadsAndChecksTheFingerprint() {
        val dest = File.createTempFile("update", ".apk").apply { delete() }
        var lastProgress = 0L
        val file = Updates.download(direct(), web.url("/releases/download/latest/ScannerIP.apk").toString(), dest, apkSha) { done, _ ->
            lastProgress = done
        }
        assertContentEquals(apk, file.readBytes())
        assertEquals(apk.size.toLong(), lastProgress)
        file.delete()
    }

    @Test
    fun aWrongFingerprintThrowsTheFileAway() {
        val dest = File.createTempFile("update", ".apk").apply { delete() }
        val wrong = "0".repeat(64)
        val e = assertFailsWith<UpdateError> {
            Updates.download(direct(), web.url("/releases/download/latest/ScannerIP.apk").toString(), dest, wrong)
        }
        assertTrue("fingerprint" in e.message!!)
        assertFalse(dest.exists())
    }

    @Test
    fun aMissingFileIsAnErrorNotAHalfDownload() {
        val dest = File.createTempFile("update", ".apk").apply { delete() }
        assertFailsWith<UpdateError> { Updates.download(direct(), web.url("/gone.apk").toString(), dest, apkSha) }
        assertFalse(dest.exists())
    }

    @Test
    fun worksThroughTheShieldToo() {
        FakeSocksProxy(InetSocketAddress("127.0.0.1", web.port)).use { proxy ->
            val viaTor = Net.client(Route.Socks("127.0.0.1", proxy.port, "sip-x-1", "x"), followRedirects = true)
            val info = Updates.fetchInfo(viaTor, "http://github.invalid/releases/download/latest/version.json")
            assertEquals(12, info.versionCode)
            assertTrue(proxy.requests.all { it.host == "github.invalid" && it.addressType == 3 })
        }
    }
}
