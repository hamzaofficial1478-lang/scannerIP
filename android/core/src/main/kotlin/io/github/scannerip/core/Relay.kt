package io.github.scannerip.core

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Base64
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * A SOCKS5 front door for ScannerIP's built-in browser.
 *
 * Android's WebView can be pointed at a proxy, but only a plain one. It can't
 * log in to it, and our Tor trick needs a login: a different SOCKS username
 * per shift is what gets a fresh circuit and so a fresh IP. Proxy-list mode
 * may also need a password, or an HTTP proxy. So the browser talks to this
 * little server on 127.0.0.1, and it makes each connection onwards through
 * whatever route [route] hands it, login included.
 *
 * Site names go onwards untouched, so nothing is looked up on the phone's own
 * connection (no DNS leak). It only listens on the phone itself, and only
 * while the browser is open.
 */
class SocksRelay(private val route: () -> Route) : AutoCloseable {
    private val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    private val open: MutableSet<Socket> = Collections.newSetFromMap(ConcurrentHashMap())

    val port: Int get() = server.localPort

    init {
        thread(isDaemon = true, name = "socks-relay") {
            while (!server.isClosed) {
                val client = try { server.accept() } catch (_: IOException) { break }
                thread(isDaemon = true, name = "socks-relay-conn") { serve(client) }
            }
        }
    }

    /** Cut every connection, so the next page load starts on the current route. */
    fun dropConnections() {
        open.toList().forEach { closeQuietly(it) }
        open.clear()
    }

    override fun close() {
        closeQuietly(server)
        dropConnections()
    }

    private fun serve(client: Socket) {
        open += client
        var upstream: Socket? = null
        try {
            client.soTimeout = HANDSHAKE_TIMEOUT_MS
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()

            if (input.readUnsignedByte() != 5) return
            val methods = ByteArray(input.readUnsignedByte()).also(input::readFully)
            if (0.toByte() !in methods) { // we only offer "no login" on the phone side
                output.write(byteArrayOf(5, 0xff.toByte()))
                return
            }
            output.write(byteArrayOf(5, 0))

            val version = input.readUnsignedByte()
            val command = input.readUnsignedByte()
            input.readUnsignedByte() // reserved
            val host = when (input.readUnsignedByte()) {
                1 -> IpLiteral.format(ByteArray(4).also(input::readFully))
                4 -> IpLiteral.format(ByteArray(16).also(input::readFully))
                3 -> String(ByteArray(input.readUnsignedByte()).also(input::readFully), Charsets.US_ASCII)
                else -> { reply(output, 8); return }
            }
            val port = input.readUnsignedShort()
            if (version != 5 || command != 1) { // CONNECT only: no listening, no UDP
                reply(output, 7)
                return
            }

            val outbound = try {
                connect(route(), host, port)
            } catch (_: SocksException) {
                reply(output, 4) // the proxy couldn't reach the site
                return
            } catch (_: Exception) {
                reply(output, 1)
                return
            }
            upstream = outbound
            open += outbound
            reply(output, 0)
            client.soTimeout = 0
            pipe(client, outbound)
        } catch (_: IOException) {
            // The browser or the far end hung up; nothing to report.
        } finally {
            closeQuietly(client)
            upstream?.let(::closeQuietly)
            open -= client
            upstream?.let { open -= it }
        }
    }

    private fun reply(output: OutputStream, code: Int) {
        output.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
        output.flush()
    }

    /** Copy both ways until both sides have finished. */
    private fun pipe(a: Socket, b: Socket) {
        val back = thread(isDaemon = true, name = "socks-relay-pipe") { copy(b, a) }
        copy(a, b)
        back.join()
    }

    private fun copy(from: Socket, to: Socket) {
        try {
            from.getInputStream().copyTo(to.getOutputStream())
            to.shutdownOutput()
        } catch (_: IOException) {
            closeQuietly(from)
            closeQuietly(to)
        }
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 20_000
        private const val HANDSHAKE_TIMEOUT_MS = 30_000

        /** Open a connection to host:port through [route], passing the name along unresolved. */
        fun connect(route: Route, host: String, port: Int): Socket {
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(route.host, route.port), CONNECT_TIMEOUT_MS)
                socket.soTimeout = HANDSHAKE_TIMEOUT_MS
                when (route) {
                    is Route.Socks -> Socks5.handshake(socket.getInputStream(), socket.getOutputStream(),
                        host, port, route.username, route.password)
                    is Route.Http -> httpConnect(socket, route, host, port)
                }
                socket.soTimeout = 0
                return socket
            } catch (e: Exception) {
                closeQuietly(socket)
                throw e
            }
        }

        private fun httpConnect(socket: Socket, route: Route.Http, host: String, port: Int) {
            val target = (if (':' in host) "[$host]" else host) + ":$port"
            val request = buildString {
                append("CONNECT $target HTTP/1.1\r\nHost: $target\r\n")
                if (route.username != null) {
                    val login = "${route.username}:${route.password.orEmpty()}".toByteArray()
                    append("Proxy-Authorization: Basic ${Base64.getEncoder().encodeToString(login)}\r\n")
                }
                append("\r\n")
            }
            socket.getOutputStream().apply { write(request.toByteArray(Charsets.ISO_8859_1)); flush() }
            val input = socket.getInputStream()
            val status = readLine(input)
            while (readLine(input).isNotEmpty()) { /* skip the headers */ }
            val code = status.split(' ').getOrNull(1)?.toIntOrNull()
            if (code != 200) throw SocksException("HTTP proxy said: $status")
        }

        // Byte by byte on purpose: anything after the headers belongs to the site.
        private fun readLine(input: InputStream): String {
            val line = StringBuilder()
            while (true) {
                val b = input.read()
                if (b < 0) throw IOException("Proxy closed the connection")
                if (b == '\n'.code) return line.toString().trimEnd('\r')
                if (line.length > 8192) throw IOException("Proxy sent a header line that's far too long")
                line.append(b.toChar())
            }
        }

        private fun closeQuietly(c: AutoCloseable) {
            try { c.close() } catch (_: Exception) {}
        }
    }
}
