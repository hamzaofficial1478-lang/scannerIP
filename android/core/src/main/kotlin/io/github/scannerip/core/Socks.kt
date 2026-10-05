package io.github.scannerip.core

import okhttp3.Dns
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import javax.net.SocketFactory

class SocksException(message: String) : IOException(message)

/**
 * A tiny SOCKS5 client (RFC 1928, with RFC 1929 username/password).
 *
 * Why not Java's built-in SOCKS support? Two reasons. It looks up the website's
 * name on your own connection before handing it to the proxy, which leaks every
 * site you visit to whoever runs your DNS (a "DNS leak"). And it can't easily
 * send a different username per request, which is the trick that makes Tor
 * give us a fresh circuit on every IP shift. This version always sends the
 * name itself, so Tor does the lookup at the far end.
 */
object Socks5 {
    fun handshake(input: InputStream, output: OutputStream, host: String, port: Int,
                  username: String? = null, password: String? = null) {
        require(port in 1..65535) { "bad port $port" }
        val useAuth = username != null
        // Offer only the method we want: with credentials, Tor isolates by them.
        output.write(byteArrayOf(5, 1, if (useAuth) 2 else 0))
        output.flush()
        val choice = readFully(input, 2)
        if (choice[0].toInt() != 5) throw SocksException("Not a SOCKS5 proxy")
        when (choice[1].toInt() and 0xff) {
            0x00 -> {}
            0x02 -> {
                val user = username.orEmpty().toByteArray()
                val pass = password.orEmpty().toByteArray()
                require(user.size in 1..255 && pass.size in 1..255)
                output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass)
                output.flush()
                val status = readFully(input, 2)
                if (status[1].toInt() != 0) throw SocksException("Proxy rejected the login")
            }
            0xff -> throw SocksException("Proxy refused every login method we offered")
            else -> throw SocksException("Proxy chose an unsupported login method")
        }

        val address = IpLiteral.parseV4(host)?.let { byteArrayOf(1) + it }
            ?: IpLiteral.parseV6(host.removePrefix("[").removeSuffix("]"))?.let { byteArrayOf(4) + it }
            ?: host.toByteArray(Charsets.US_ASCII).let {
                require(it.size in 1..255) { "host name too long" }
                byteArrayOf(3, it.size.toByte()) + it
            }
        output.write(byteArrayOf(5, 1, 0) + address + byteArrayOf((port shr 8).toByte(), port.toByte()))
        output.flush()

        val reply = readFully(input, 4)
        val code = reply[1].toInt() and 0xff
        if (code != 0) throw SocksException(REPLY_MESSAGES[code] ?: "Proxy error $code")
        when (reply[3].toInt()) { // skip the bound address the proxy reports back
            1 -> readFully(input, 4 + 2)
            4 -> readFully(input, 16 + 2)
            3 -> readFully(input, (readFully(input, 1)[0].toInt() and 0xff) + 2)
            else -> throw SocksException("Proxy sent a strange reply")
        }
    }

    private val REPLY_MESSAGES = mapOf(
        1 to "Proxy: general failure",
        2 to "Proxy: connection not allowed",
        3 to "Proxy: network unreachable",
        4 to "Proxy: host unreachable (the site may be down or blocking Tor)",
        5 to "Proxy: connection refused",
        6 to "Proxy: timed out",
        7 to "Proxy: command not supported",
        8 to "Proxy: address type not supported",
    )

    private fun readFully(input: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val read = input.read(buf, off, n - off)
            if (read < 0) throw EOFException("Proxy closed the connection")
            off += read
        }
        return buf
    }
}

/** A socket that goes through a SOCKS5 proxy when OkHttp connects it. */
class Socks5Socket(
    private val proxy: InetSocketAddress,
    private val username: String?,
    private val password: String?,
) : Socket() {
    override fun connect(endpoint: SocketAddress, timeout: Int) {
        val target = endpoint as? InetSocketAddress ?: throw IllegalArgumentException("Unsupported address")
        super.connect(proxy, timeout)
        val previous = soTimeout
        soTimeout = if (timeout > 0) timeout else 20_000
        try {
            // hostString gives the name we were asked for, never a DNS answer.
            Socks5.handshake(getInputStream(), getOutputStream(), target.hostString, target.port, username, password)
        } catch (e: IOException) {
            close()
            throw e
        }
        soTimeout = previous
    }

    override fun connect(endpoint: SocketAddress) = connect(endpoint, 0)
}

class Socks5SocketFactory(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val username: String? = null,
    private val password: String? = null,
) : SocketFactory() {
    private fun proxyAddress() = InetSocketAddress(proxyHost, proxyPort)

    override fun createSocket(): Socket = Socks5Socket(proxyAddress(), username, password)

    override fun createSocket(host: String, port: Int): Socket =
        createSocket().apply { connect(InetSocketAddress.createUnresolved(host, port)) }

    override fun createSocket(host: String, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        createSocket(host, port)

    override fun createSocket(host: InetAddress, port: Int): Socket =
        createSocket().apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        createSocket(address, port)
}

/**
 * OkHttp insists on "resolving" names before it connects. This hands back a
 * placeholder address that still carries the name, so nothing is looked up
 * locally and [Socks5Socket] can pass the name on to the proxy.
 */
object NoLocalDns : Dns {
    override fun lookup(hostname: String): List<InetAddress> =
        listOf(InetAddress.getByAddress(hostname, ByteArray(4)))
}
