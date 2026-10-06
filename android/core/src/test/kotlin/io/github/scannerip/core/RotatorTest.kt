package io.github.scannerip.core

import java.net.ServerSocket
import java.security.SecureRandom
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RotatorTest {
    private fun vault() = IdentityVault(SoftwareKeys(ByteArray(32).also(SecureRandom()::nextBytes)), "test-device".toByteArray())

    private fun waitFor(seconds: Double = 3.0, condition: () -> Boolean) {
        val end = System.nanoTime() + (seconds * 1e9).toLong()
        while (!condition() && System.nanoTime() < end) Thread.sleep(10)
    }

    @Test
    fun simulatedIpsAreDocumentationAddresses() {
        val r = SimulatedRotator(seed = 1)
        val ips = (1..30).map { r.rotate().ip }
        assertTrue(ips.all { ip -> DOC_NETWORKS.any { ip.startsWith(it) } })
        assertTrue(ips.zipWithNext().all { (a, b) -> a != b })
        assertFalse(r.anonymous)
        assertFailsWith<RotationError> { r.route() } // never pretends to carry real traffic
    }

    @Test
    fun proxyPoolSkipsDeadProxies() {
        val answers = mapOf(Route.parse("p1:8080") to "198.51.100.1", Route.parse("socks5h://p3:1080") to "198.51.100.3")
        val r = ProxyPoolRotator(
            listOf("p1:8080", "# comment", "http://p2:8080", "", "socks5h://p3:1080  # tor-ish"),
            lookup = { route -> ExitLookup(answers[route] ?: throw java.io.IOException("dead"), false) },
        )
        assertFailsWith<RotationError> { r.route() }
        assertEquals("198.51.100.1", r.rotate().ip)
        assertEquals(Route.Http("p1", 8080), r.route())
        assertEquals("198.51.100.3", r.rotate().ip) // p2 is dead, skipped
        assertEquals("198.51.100.1", r.rotate().ip) // wraps round
    }

    @Test
    fun proxyPoolAllDeadOrEmpty() {
        val r = ProxyPoolRotator(listOf("http://a:1"), lookup = { throw java.io.IOException("nope") })
        assertFailsWith<RotationError> { r.rotate() }
        assertFailsWith<RotationError> { r.route() }
        assertFailsWith<RotationError> { ProxyPoolRotator(listOf("# nothing", "  ")) }
        assertFailsWith<RotationError> { ProxyPoolRotator(listOf("ftp://bad:21")) }
    }

    @Test
    fun torUsesANewSocksIdentityEachShift() {
        val seen = mutableListOf<Route>()
        val ips = mutableListOf("185.220.101.1", "185.220.101.1", "185.220.101.2", "185.220.101.3").iterator()
        var newnyms = 0
        val r = TorRotator(socksPort = 9050, newIdentity = { newnyms++ }, lookup = { route ->
            seen += route
            ExitLookup(ips.next(), true)
        })
        val first = r.rotate()
        val second = r.rotate() // first try gives the same IP, so it tries one more circuit
        assertEquals("185.220.101.1", first.ip)
        assertEquals("185.220.101.2", second.ip)
        assertEquals(true, first.isTor)
        assertEquals(3, seen.size)
        assertEquals(3, seen.map { (it as Route.Socks).username }.toSet().size)
        assertEquals(3, newnyms)
    }

    @Test
    fun torKeepsGoingIfNewnymFails() {
        val r = TorRotator(newIdentity = { error("control port gone") }, lookup = { ExitLookup("185.220.101.9", true) })
        assertEquals("185.220.101.9", r.rotate().ip)
    }

    @Test
    fun aFailedShiftFallsBackToTheLastCheckedCircuit() {
        var fail = false
        val r = TorRotator(isUp = { true }, lookup = { if (fail) throw java.io.IOException("timeout") else ExitLookup("185.220.101.5", true) })
        r.rotate()
        val good = r.route()
        fail = true
        val e = assertFailsWith<RotationError> { r.rotate() }
        assertFalse(e.unreachable) // Tor answered; the new circuit was just slow
        assertEquals(good, r.route()) // still the circuit whose exit we checked
    }

    @Test
    fun torNotAnsweringIsToldApartFromASlowCircuit() {
        val r = TorRotator(isUp = { false }, lookup = { throw java.net.SocketTimeoutException("failed to connect") })
        assertTrue(assertFailsWith<RotationError> { r.rotate() }.unreachable)
    }

    @Test
    fun proxyPoolKeepsTheLastWorkingProxyThroughABlip() {
        var up = true
        val r = ProxyPoolRotator(listOf("http://a:1"), lookup = { if (up) ExitLookup("198.51.100.9", false) else throw java.io.IOException("blip") })
        r.rotate()
        up = false
        assertFailsWith<RotationError> { r.rotate() }
        assertEquals(Route.Http("a", 1), r.route())
    }

    @Test
    fun shieldRetriesSoonAfterAFailedShift() {
        var calls = 0
        val flaky = object : Rotator by SimulatedRotator() {
            val inner = SimulatedRotator()
            override fun rotate(): ExitInfo {
                calls++
                if (calls == 1) throw RotationError("slow circuit")
                return inner.rotate()
            }
        }
        val events = java.util.Collections.synchronizedList(mutableListOf<RotationEvent>())
        val shield = Shield(flaky, vault(), onRotate = { events += it }, retryMillis = 50)
        shield.intervalMillis = 60_000 // a full interval would be a minute
        shield.start()
        waitFor { events.isNotEmpty() }
        shield.stop()
        assertEquals(1, events.size) // the retry came after 50 ms, not a minute
    }

    @Test
    fun spotsWhetherSomethingIsListening() {
        ServerSocket(0).use { server -> assertTrue(TorRotator.isListening("127.0.0.1", server.localPort)) }
        val closed = ServerSocket(0).use { it.localPort }
        assertFalse(TorRotator.isListening("127.0.0.1", closed))
    }

    @Test
    fun shieldRotatesIpAndIdentityTogether() {
        val events = java.util.Collections.synchronizedList(mutableListOf<RotationEvent>())
        val shield = Shield(SimulatedRotator(seed = 3), vault(), intervalSeconds = 0, onRotate = { events += it })
        assertEquals(2000L, shield.intervalMillis) // clamped to the rotator's minimum
        shield.intervalMillis = 30 // speed things up for the test
        shield.start()
        waitFor { events.size >= 3 }
        shield.stop()
        assertTrue(events.size >= 3)
        val snapshot = events.toList()
        assertEquals(snapshot.size, snapshot.map { it.exit.ip }.toSet().size)
        assertEquals(snapshot.size, snapshot.map { it.identity.rotatingId }.toSet().size)
        assertTrue(snapshot.all { it.identity.exitIp == it.exit.ip })
        assertFalse(shield.running)
        assertNull(shield.secondsLeft())
    }

    @Test
    fun shieldReportsErrorsAndKeepsGoing() {
        var calls = 0
        val flaky = object : Rotator by SimulatedRotator() {
            val inner = SimulatedRotator()
            override fun rotate(): ExitInfo {
                calls++
                if (calls == 1) throw RotationError("blip")
                return inner.rotate()
            }
        }
        val errors = mutableListOf<Exception>()
        val events = mutableListOf<RotationEvent>()
        val shield = Shield(flaky, vault(), onRotate = { events += it }, onError = { errors += it })
        shield.intervalMillis = 20
        shield.start()
        waitFor { events.isNotEmpty() }
        shield.stop()
        assertTrue(errors.isNotEmpty() && events.isNotEmpty())
    }

    @Test
    fun pausingAndResumingKeepsJustOneTimer() {
        // The shielded browser pauses the timer and resumes it later, sometimes
        // while a shift is still half-way through. That mustn't leave two timers.
        val gate = java.util.concurrent.CountDownLatch(1)
        val calls = java.util.concurrent.atomic.AtomicInteger()
        val slow = object : Rotator by SimulatedRotator() {
            val inner = SimulatedRotator()
            override fun rotate(): ExitInfo {
                if (calls.incrementAndGet() == 1) gate.await()
                return inner.rotate()
            }
        }
        val shield = Shield(slow, vault(), intervalSeconds = 600)
        shield.start()
        waitFor { calls.get() == 1 } // the first shift is stuck half-way
        shield.stop(waitMillis = 0)
        assertNull(shield.secondsLeft())
        shield.start()
        gate.countDown()
        waitFor { calls.get() >= 2 }
        Thread.sleep(300)
        assertEquals(1, Thread.getAllStackTraces().keys.count { it.name == "ip-shield" && it.isAlive })
        assertTrue(shield.running)
        shield.stop()
    }

    @Test
    fun stopWakesTheTimerStraightAway() {
        val shield = Shield(SimulatedRotator(), vault(), intervalSeconds = 600)
        shield.start()
        waitFor { shield.current != null }
        val started = System.nanoTime()
        shield.stop()
        assertTrue((System.nanoTime() - started) / 1e9 < 2, "stop() should not wait for the 10 minute sleep")
    }

    @Test
    fun rotateNowIsThreadSafe() {
        val shield = Shield(SimulatedRotator(), vault())
        (1..10).map { thread { shield.rotateNow() } }.forEach { it.join() }
        assertEquals(10, shield.vault.rotation)
        assertEquals(10, shield.history.size)
    }

    @Test
    fun historyIsCapped() {
        val shield = Shield(SimulatedRotator(), vault(), historySize = 5)
        repeat(12) { shield.rotateNow() }
        assertEquals(5, shield.history.size)
        assertEquals(12, shield.history.last().identity.rotation)
    }
}
