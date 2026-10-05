package io.github.scannerip.core

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NetTest {
    private lateinit var web: MockWebServer
    private lateinit var proxy: FakeSocksProxy

    @BeforeTest
    fun setUp() {
        web = MockWebServer().apply { start() }
        proxy = FakeSocksProxy(InetSocketAddress("127.0.0.1", web.port))
    }

    @AfterTest
    fun tearDown() {
        proxy.close()
        web.shutdown()
    }

    @Test
    fun namesTravelToTheProxyNotToLocalDns() {
        web.enqueue(MockResponse().setBody("""{"IsTor": true, "IP": "185.220.101.7"}"""))
        val route = Route.Socks("127.0.0.1", proxy.port, "sip-abc-1", "x")
        // ".invalid" can never resolve, so this only works if the name goes to the proxy.
        val found = Net.lookupExitIp(route, listOf("http://ipcheck.invalid/api/ip"))
        assertEquals(ExitLookup("185.220.101.7", true), found)
        val asked = proxy.requests.single()
        assertEquals(3, asked.addressType) // 3 = domain name
        assertEquals("ipcheck.invalid", asked.host)
        assertEquals(80, asked.port)
        assertEquals("sip-abc-1", asked.username) // what Tor uses to pick a circuit
        assertEquals("ipcheck.invalid", web.takeRequest().getHeader("Host"))
    }

    @Test
    fun ipLiteralsUseTheIpAddressType() {
        web.enqueue(MockResponse().setBody("""{"ip": "198.51.100.4"}"""))
        Net.lookupExitIp(Route.Socks("127.0.0.1", proxy.port), listOf("http://203.0.113.9/"))
        val asked = proxy.requests.single()
        assertEquals(1, asked.addressType)
        assertEquals("203.0.113.9", asked.host)
        assertNull(asked.username)
    }

    @Test
    fun lookupFallsBackToTheNextServiceAndValidatesTheAnswer() {
        web.enqueue(MockResponse().setResponseCode(500))
        web.enqueue(MockResponse().setBody("""{"ip": "not an ip"}"""))
        web.enqueue(MockResponse().setBody("""{"ip": "198.51.100.77"}"""))
        val route = Route.Socks("127.0.0.1", proxy.port)
        val urls = listOf("http://one.invalid/", "http://two.invalid/", "http://three.invalid/")
        assertEquals(ExitLookup("198.51.100.77", null), Net.lookupExitIp(route, urls))
    }

    @Test
    fun lookupFailsCleanlyWhenNothingAnswers() {
        val closedPort = ServerSocket(0).use { it.localPort }
        assertFailsWith<RotationError> {
            Net.lookupExitIp(Route.Socks("127.0.0.1", closedPort), listOf("http://x.invalid/"), timeoutSeconds = 2)
        }
    }

    @Test
    fun cookiesAreNeverStored() {
        web.enqueue(MockResponse().addHeader("Set-Cookie", "track=me").setBody("""{"ip": "192.0.2.1"}"""))
        web.enqueue(MockResponse().setBody("""{"ip": "192.0.2.1"}"""))
        val client = Net.client(Route.Socks("127.0.0.1", proxy.port))
        repeat(2) {
            client.newCall(okhttp3.Request.Builder().url("http://site.invalid/").build()).execute().close()
        }
        web.takeRequest()
        assertNull(web.takeRequest().getHeader("Cookie"))
    }

    @Test
    fun parsesProxyLines() {
        assertEquals(Route.Http("p1", 8080), Route.parse("p1:8080"))
        assertEquals(Route.Http("proxy.example", 3128, "me", "p@ss"), Route.parse("http://me:p%40ss@proxy.example:3128"))
        assertEquals(Route.Socks("127.0.0.1", 9050), Route.parse("socks5h://127.0.0.1:9050"))
        assertEquals(Route.Socks("tor", 1080), Route.parse("socks5://tor"))
        assertFailsWith<IllegalArgumentException> { Route.parse("ftp://nope:21") }
        assertTrue(Route.parse("SOCKS5H://H:1") is Route.Socks)
    }
}
