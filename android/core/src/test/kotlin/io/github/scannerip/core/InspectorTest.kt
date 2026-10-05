package io.github.scannerip.core

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.io.File
import java.net.InetSocketAddress
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class InspectorTest {
    private val web = MockWebServer()
    private lateinit var proxy: FakeSocksProxy

    /** Serve pages by "host + path", all through the fake Tor proxy. */
    private fun serve(pages: Map<String, (RecordedRequest) -> MockResponse>): Route {
        web.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val key = request.getHeader("Host")!!.substringBefore(':') + request.path
                return pages[key]?.invoke(request) ?: MockResponse().setResponseCode(404)
            }
        }
        web.start()
        proxy = FakeSocksProxy(InetSocketAddress("127.0.0.1", web.port))
        return Route.Socks("127.0.0.1", proxy.port, "sip-test-1", "x")
    }

    @AfterTest
    fun tearDown() {
        if (::proxy.isInitialized) proxy.close()
        web.shutdown()
    }

    private fun redirect(to: String) = MockResponse().setResponseCode(302).addHeader("Location", to)

    @Test
    fun refusesWithoutTheShield() {
        val e = assertFailsWith<IllegalArgumentException> { inspectUrl("https://bit.ly/x", null) }
        assertTrue("real IP" in e.message!!)
        assertFailsWith<IllegalArgumentException> { inspectUrl("javascript:alert(1)", Route.Socks("127.0.0.1", 1)) }
    }

    @Test
    fun followsAShortenerToAnApk() {
        val route = serve(mapOf(
            "short.invalid/x" to { _ -> redirect("http://step.invalid/go") },
            "step.invalid/go" to { _ -> redirect("/files/app.apk").addHeader("Set-Cookie", "id=123") },
            "step.invalid/files/app.apk" to { _ ->
                MockResponse().addHeader("Content-Type", "application/vnd.android.package-archive")
            },
        ))
        val result = inspectUrl("http://short.invalid/x", route)
        assertEquals(listOf("http://short.invalid/x", "http://step.invalid/go", "http://step.invalid/files/app.apk"),
            result.hops.map { it.url })
        assertEquals(Level.DANGEROUS, result.report!!.level)
        assertTrue(result.extra.any { it.severity == Severity.CRITICAL })
        val requests = (1..3).map { web.takeRequest() }
        assertTrue(requests.all { it.method == "HEAD" })
        assertTrue(requests.all { "Firefox" in it.getHeader("User-Agent")!! })
        assertTrue(requests.none { it.getHeader("Cookie") != null }, "cookies must not be carried between hops")
        assertTrue(proxy.requests.all { it.username == "sip-test-1" && it.addressType == 3 })
    }

    @Test
    fun fallsBackToGetWhenHeadIsRefused() {
        val route = serve(mapOf("shop.invalid/" to { r ->
            if (r.method == "HEAD") MockResponse().setResponseCode(405)
            else MockResponse().addHeader("Content-Type", "text/html").setBody("<html>secret page body</html>")
        }))
        val result = inspectUrl("http://shop.invalid/", route)
        assertEquals(listOf("HEAD", "GET"), listOf(web.takeRequest().method, web.takeRequest().method))
        assertEquals(200, result.hops.last().status)
    }

    @Test
    fun redirectLoopIsCapped() {
        val route = serve(mapOf("loop.invalid/" to { _ -> redirect("http://loop.invalid/") }))
        val result = inspectUrl("http://loop.invalid/", route, maxHops = 4)
        assertEquals(4, result.hops.size)
        assertTrue(result.extra.any { "More than 4 redirects" in it.message })
    }

    @Test
    fun redirectToANonWebSchemeStops() {
        val route = serve(mapOf("a.invalid/" to { _ -> redirect("intent://scan#Intent;end") }))
        val result = inspectUrl("http://a.invalid/", route)
        assertTrue(result.extra.any { "non-web" in it.message })
    }

    @Test
    fun forcedDownloadIsFlagged() {
        val route = serve(mapOf("dl.invalid/" to { _ ->
            MockResponse().addHeader("Content-Disposition", "attachment; filename=\"invoice.pdf.exe\"")
        }))
        val result = inspectUrl("http://dl.invalid/", route)
        assertTrue(result.extra.any { it.severity == Severity.CRITICAL && "invoice.pdf.exe" in it.message })
    }

    @Test
    fun networkErrorIsReportedNotThrown() {
        val closed = java.net.ServerSocket(0).use { it.localPort }
        val result = inspectUrl("http://down.invalid/", Route.Socks("127.0.0.1", closed), timeoutSeconds = 2)
        assertTrue(result.error.isNotEmpty())
        assertTrue(result.hops.isEmpty())
    }

    @Test
    fun scanLogRoundTrip() {
        val file = File.createTempFile("scanlog", ".jsonl").apply { delete() }
        val log = ScanLog(file)
        val vault = IdentityVault(SoftwareKeys(ByteArray(32) { 7 }), "x".toByteArray())
        log.record("QR Code", analyseText("https://www.bbc.co.uk/news"), vault.rotate("192.0.2.1"))
        log.record("Aztec", analyseText("https://free-updates.example/whatsapp-gold.apk"), null)
        file.appendText("this line is broken\n")
        val entries = log.readAll()
        assertEquals(listOf("CLEAN", "DANGEROUS"), entries.map { it.level })
        assertTrue(entries[0].rotatingId!!.startsWith("RID-"))
        assertEquals("url", entries[1].kind)
        assertTrue(entries[1].findings.any { it.startsWith("critical:") })
        log.clear()
        assertTrue(log.readAll().isEmpty())
    }
}
