package io.github.scannerip.core

import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import kotlin.concurrent.thread

/**
 * A pretend Tor: a SOCKS5 server that records what it was asked for and then
 * relays every connection to one local test server, whatever name was asked
 * for. Names ending in ".invalid" can never resolve, so if a request through
 * here works, the name must have travelled to the proxy rather than being
 * looked up on our side.
 */
class FakeSocksProxy(private val target: InetSocketAddress) : AutoCloseable {
    data class Request(val username: String?, val password: String?, val addressType: Int, val host: String, val port: Int)

    private val server = ServerSocket(0)
    val port: Int get() = server.localPort
    val requests: MutableList<Request> = Collections.synchronizedList(mutableListOf())

    init {
        thread(isDaemon = true, name = "fake-socks") {
            while (!server.isClosed) {
                val client = try { server.accept() } catch (_: Exception) { break }
                thread(isDaemon = true) { handle(client) }
            }
        }
    }

    private fun handle(client: Socket) = client.use {
        val input = DataInputStream(client.getInputStream())
        val output = client.getOutputStream()
        check(input.readUnsignedByte() == 5)
        val methods = ByteArray(input.readUnsignedByte()).also(input::readFully)
        var user: String? = null
        var pass: String? = null
        if (2.toByte() in methods) {
            output.write(byteArrayOf(5, 2))
            check(input.readUnsignedByte() == 1)
            user = String(ByteArray(input.readUnsignedByte()).also(input::readFully))
            pass = String(ByteArray(input.readUnsignedByte()).also(input::readFully))
            output.write(byteArrayOf(1, 0))
        } else {
            output.write(byteArrayOf(5, 0))
        }
        check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 1 && input.readUnsignedByte() == 0)
        val type = input.readUnsignedByte()
        val host = when (type) {
            1 -> IpLiteral.format(ByteArray(4).also(input::readFully))
            4 -> IpLiteral.format(ByteArray(16).also(input::readFully))
            3 -> String(ByteArray(input.readUnsignedByte()).also(input::readFully))
            else -> error("bad address type")
        }
        val port = input.readUnsignedShort()
        requests += Request(user, pass, type, host, port)
        val upstream = Socket()
        upstream.connect(target)
        output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0))
        output.flush()
        val t = thread(isDaemon = true) { pipe(upstream.getInputStream(), output) }
        pipe(input, upstream.getOutputStream())
        t.join(2000)
        upstream.close()
    }

    private fun pipe(from: InputStream, to: OutputStream) {
        try { from.copyTo(to); to.flush() } catch (_: Exception) {}
    }

    override fun close() = server.close()
}
