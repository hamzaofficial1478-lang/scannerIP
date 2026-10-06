package io.github.scannerip.core

import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RelayTest {
    private lateinit var web: MockWebServer
    private lateinit var tor: FakeSocksProxy
    @Volatile private var route: Route = Route.Socks("127.0.0.1", 1)
    private lateinit var relay: SocksRelay

    @BeforeTest
    fun setUp() {
        web = MockWebServer().apply { start() }
        tor = FakeSocksProxy(InetSocketAddress("127.0.0.1", web.port))
        route = Route.Socks("127.0.0.1", tor.port, "sip-abc-1", "x")
        relay = SocksRelay { route }
    }

    @AfterTest
    fun tearDown() {
        relay.close()
        tor.close()
        web.shutdown()
    }

    /** What the WebView does: plain SOCKS5, no login, the site's name unresolved. */
    private fun browse(url: String): String =
        Net.client(Route.Socks("127.0.0.1", relay.port)).newCall(Request.Builder().url(url).build()).execute()
            .use { it.body!!.string() }

    @Test
    fun browserTrafficPicksUpTheShieldLogin() {
        web.enqueue(MockResponse().setBody("hello from the site"))
        assertEquals("hello from the site", browse("http://quiz.invalid/start"))
        val asked = tor.requests.single()
        assertEquals("sip-abc-1", asked.username) // so Tor uses this shift's circuit
        assertEquals(3, asked.addressType)
        assertEquals("quiz.invalid", asked.host) // never looked up on the phone
        assertEquals("quiz.invalid", web.takeRequest().getHeader("Host"))
    }

    @Test
    fun aNewShiftAppliesToNewConnections() {
        web.enqueue(MockResponse().setBody("one"))
        web.enqueue(MockResponse().setBody("two"))
        browse("http://a.invalid/")
        route = Route.Socks("127.0.0.1", tor.port, "sip-abc-2", "x")
        relay.dropConnections()
        browse("http://b.invalid/")
        assertEquals(listOf("sip-abc-1", "sip-abc-2"), tor.requests.map { it.username })
    }

    @Test
    fun httpProxiesGetAConnectWithTheLogin() {
        val seen = Collections.synchronizedList(mutableListOf<String>())
        val proxy = ServerSocket(0)
        thread(isDaemon = true) {
            proxy.accept().use { client ->
                val input = DataInputStream(client.getInputStream())
                val lines = generateSequence { readAsciiLine(input) }.takeWhile { it.isNotEmpty() }.toList()
                seen += lines
                client.getOutputStream().write("HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\n".toByteArray())
                Socket("127.0.0.1", web.port).use { site ->
                    val back = thread(isDaemon = true) { site.getInputStream().copyTo(client.getOutputStream()) }
                    input.copyTo(site.getOutputStream())
                    back.join(2000)
                }
            }
        }
        route = Route.Http("127.0.0.1", proxy.localPort, "alice", "s3cret")
        web.enqueue(MockResponse().setBody("via http proxy"))
        assertEquals("via http proxy", browse("http://shop.invalid:8081/"))
        assertEquals("CONNECT shop.invalid:8081 HTTP/1.1", seen.first())
        assertTrue("Proxy-Authorization: Basic YWxpY2U6czNjcmV0" in seen) // alice:s3cret
        proxy.close()
    }

    private fun handshake(methods: ByteArray, request: ByteArray?): ByteArray {
        Socket("127.0.0.1", relay.port).use { s ->
            s.soTimeout = 5000
            val out = s.getOutputStream()
            val input = DataInputStream(s.getInputStream())
            out.write(byteArrayOf(5, methods.size.toByte()) + methods)
            val choice = ByteArray(2).also(input::readFully)
            if (request == null || choice[1] != 0.toByte()) return choice
            out.write(request)
            return ByteArray(10).also(input::readFully)
        }
    }

    private val example = byteArrayOf(3, 11) + "example.com".toByteArray() + byteArrayOf(0, 80)

    @Test
    fun onlyPlainConnectIsAllowed() {
        // UDP or listening could sneak round the shield, so they're refused.
        assertEquals(7, handshake(byteArrayOf(0), byteArrayOf(5, 3, 0) + example)[1].toInt())
        assertEquals(7, handshake(byteArrayOf(0), byteArrayOf(5, 2, 0) + example)[1].toInt())
        // A client that only wants to log in gets "no acceptable methods".
        assertEquals(0xff, handshake(byteArrayOf(2), null)[1].toInt() and 0xff)
        assertTrue(tor.requests.isEmpty())
    }

    @Test
    fun noRouteMeansNoConnection() {
        route = Route.Socks("127.0.0.1", tor.port)
        val broken = SocksRelay { throw RotationError("shield is off") }
        try {
            Socket("127.0.0.1", broken.port).use { s ->
                s.soTimeout = 5000
                s.getOutputStream().write(byteArrayOf(5, 1, 0) + byteArrayOf(5, 1, 0) + example)
                val input = DataInputStream(s.getInputStream())
                ByteArray(2).also(input::readFully)
                assertEquals(1, ByteArray(10).also(input::readFully)[1].toInt()) // general failure
            }
        } finally {
            broken.close()
        }
        assertTrue(tor.requests.isEmpty())
    }

    private fun readAsciiLine(input: DataInputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) return sb.toString().trimEnd('\r')
            sb.append(b.toChar())
        }
    }
}
