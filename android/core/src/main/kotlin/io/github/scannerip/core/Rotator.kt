package io.github.scannerip.core

import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import kotlin.random.Random

/*
 * IP shifting.
 *
 * Your public IP address is what a website sees when you connect. If a QR code
 * leads to an attacker's server, that address gives away roughly where you are
 * and which network you're on, and lets them tie your visits together. The
 * rotators here push traffic through someone else's address and swap it every
 * few seconds.
 *
 *   TorRotator         real, free. Built-in Tor, or Orbot if you prefer.
 *   ProxyPoolRotator   real. Cycles through proxies you supply.
 *   SimulatedRotator   fake, for classroom demos where Tor is blocked. Uses the
 *                      RFC 5737 documentation ranges so it can never be
 *                      mistaken for a real address, and carries no traffic.
 */

/** A shift that didn't work. [unreachable] means Tor (or the proxy) itself didn't answer at all. */
class RotationError(message: String, cause: Throwable? = null, val unreachable: Boolean = false) : Exception(message, cause)

data class ExitInfo(val ip: String, val via: String, val isTor: Boolean? = null)

interface Rotator {
    val name: String

    /** True only if traffic really leaves from another address. */
    val anonymous: Boolean
    val minIntervalSeconds: Int
    val defaultIntervalSeconds: Int

    fun rotate(): ExitInfo

    /** Where to send traffic for the current exit. Throws if there isn't one. */
    fun route(): Route

    fun close() {}
}

// RFC 5737: reserved for documentation, never routed on the internet.
val DOC_NETWORKS = listOf("192.0.2.", "198.51.100.", "203.0.113.")

class SimulatedRotator(seed: Long? = null) : Rotator {
    private val rng = if (seed != null) Random(seed) else Random.Default
    private var last = ""

    override val name = "Demo (made-up IPs)"
    override val anonymous = false
    override val minIntervalSeconds = 2
    override val defaultIntervalSeconds = 5

    override fun rotate(): ExitInfo {
        while (true) {
            val ip = DOC_NETWORKS.random(rng) + rng.nextInt(1, 255)
            if (ip != last) {
                last = ip
                return ExitInfo(ip, "simulated")
            }
        }
    }

    override fun route(): Route = throw RotationError("$name doesn't carry real traffic")
}

/**
 * Gets a new Tor circuit (and so, nearly always, a new exit IP) on each shift.
 *
 * The trick is a different SOCKS username per shift. Tor's IsolateSOCKSAuth
 * (on by default) puts streams with different credentials on different
 * circuits. Tor's NEWNYM ("new identity") signal can be sent as well, but the
 * app doesn't: it throws away every circuit, including the last one that
 * worked, and that's the one to fall back on when a shift fails.
 *
 * If a shift fails (Tor is slow to build the new circuit, or the phone has
 * paused the app), the rotator goes back to the last circuit whose exit IP it
 * actually checked, so traffic keeps going out of an address we know.
 *
 * Every shift builds a fresh circuit, and the Tor Project asks people not to
 * do that needlessly because it loads the volunteer-run network. So the
 * default is a gentler 30 seconds, and never less than 10.
 */
class TorRotator(
    private val host: String = "127.0.0.1",
    private val socksPort: Int = 9050,
    override val name: String = "Tor",
    private val newIdentity: (() -> Unit)? = null,
    private val lookup: (Route) -> ExitLookup = { Net.lookupExitIp(it) },
    private val maxAttempts: Int = 2,
    private val isUp: () -> Boolean = { isListening(host, socksPort) },
) : Rotator {
    override val anonymous = true
    override val minIntervalSeconds = 10
    override val defaultIntervalSeconds = 30

    private val tag = ByteArray(4).also(SecureRandom()::nextBytes).toHex()
    @Volatile private var circuit = 0
    private var lastIp = ""

    override fun route(): Route = Route.Socks(host, socksPort, "sip-$tag-$circuit", "x")

    override fun rotate(): ExitInfo {
        val lastGood = circuit
        var found: ExitLookup? = null
        try {
            for (attempt in 1..maxAttempts) {
                circuit += 1
                try { newIdentity?.invoke() } catch (_: Exception) { /* SOCKS isolation still works */ }
                found = lookup(route())
                if (found.ip != lastIp) break // same exit by chance? try one more circuit
            }
        } catch (e: Exception) {
            circuit = lastGood // back to the circuit whose exit we know
            if (!isUp()) throw RotationError("$name isn't answering on port $socksPort", e, unreachable = true)
            throw RotationError("The new circuit didn't come up in time (${e.message})", e)
        }
        lastIp = found!!.ip
        return ExitInfo(found.ip, "Tor circuit #$circuit", found.isTor)
    }

    companion object {
        /** Is anything listening on host:port? Used to spot whether Orbot is running. */
        fun isListening(host: String, port: Int, timeoutMs: Int = 1500): Boolean = try {
            Socket().use { it.connect(InetSocketAddress(host, port), timeoutMs); true }
        } catch (_: Exception) {
            false
        }
    }
}

/** Round-robin through proxies you provide (http://, socks5://, socks5h://). */
class ProxyPoolRotator(
    proxies: List<String>,
    private val lookup: (Route) -> ExitLookup = { Net.lookupExitIp(it) },
) : Rotator {
    override val name = "Proxy list"
    override val anonymous = true
    override val minIntervalSeconds = 3
    override val defaultIntervalSeconds = 10

    private val pool: List<Route>
    private var index = -1
    @Volatile private var current: Route? = null

    init {
        val lines = proxies.map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }
        if (lines.isEmpty()) throw RotationError("The proxy list is empty.")
        pool = lines.map { line ->
            try {
                Route.parse(line)
            } catch (e: IllegalArgumentException) {
                throw RotationError("Can't read the proxy line '$line': ${e.message}")
            }
        }
    }

    override fun route(): Route = current ?: throw RotationError("No working proxy yet.")

    override fun rotate(): ExitInfo {
        repeat(pool.size) {
            index = (index + 1) % pool.size
            val candidate = pool[index]
            val found = try { lookup(candidate) } catch (_: Exception) { null } // dead proxy, skip it
            if (found != null) {
                current = candidate
                return ExitInfo(found.ip, "proxy ${index + 1}/${pool.size}", found.isTor)
            }
        }
        // Keep the last proxy that worked: this may only be a blip in the network.
        throw RotationError("None of the proxies answered.")
    }
}
