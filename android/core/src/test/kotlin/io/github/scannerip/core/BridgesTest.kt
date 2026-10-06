package io.github.scannerip.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BridgesTest {
    @Test
    fun noBridgeJustSwitchesBridgesOff() {
        assertEquals(listOf("UseBridges 0"), Bridges.torConfig(BridgeType.NONE, 0))
    }

    @Test
    fun bridgeConfigPointsTorAtTheTransportInsideTheApp() {
        val conf = Bridges.torConfig(BridgeType.SNOWFLAKE, 43210)
        assertEquals("UseBridges 1", conf[0])
        assertEquals("ClientTransportPlugin snowflake socks5 127.0.0.1:43210", conf[1])
        assertEquals(2, conf.count { it.startsWith("Bridge snowflake ") })

        val meek = Bridges.torConfig(BridgeType.MEEK, 5000)
        assertEquals("ClientTransportPlugin meek_lite socks5 127.0.0.1:5000", meek[1])
        assertTrue(meek[2].startsWith("Bridge meek_lite 192.0.2.20:80 "))

        assertFailsWith<IllegalArgumentException> { Bridges.torConfig(BridgeType.OBFS4, 0) }
    }

    @Test
    fun builtInLinesAreWellFormed() {
        for ((type, lines) in Bridges.BUILT_IN) {
            assertTrue(lines.isNotEmpty())
            for (line in lines) {
                val words = line.split(' ')
                assertEquals(type.transport, words[0], line)
                assertTrue(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+$").matches(words[1]), line)
            }
        }
        // obfs4 bridges need the relay fingerprint and the bridge's certificate.
        Bridges.BUILT_IN.getValue(BridgeType.OBFS4).forEach { line ->
            assertTrue(Regex("^[0-9A-F]{40}$").matches(line.split(' ')[2]), line)
            assertTrue("cert" in Bridges.options(line), line)
        }
    }

    @Test
    fun snowflakeOptionsCanBeReadBack() {
        val o = Bridges.options(Bridges.BUILT_IN.getValue(BridgeType.SNOWFLAKE).first())
        assertEquals("https://1098762253.rsc.cdn77.org/", o["url"])
        assertEquals("app.datapacket.com,www.datapacket.com", o["fronts"])
        assertTrue(o.getValue("ice").startsWith("stun:"))
        assertEquals(8, o.getValue("ice").split(',').size)
    }

    @Test
    fun automaticModeRemembersWhatWorked() {
        assertEquals(listOf(BridgeType.NONE, BridgeType.OBFS4, BridgeType.SNOWFLAKE, BridgeType.MEEK), Bridges.autoOrder(null))
        assertEquals(listOf(BridgeType.SNOWFLAKE, BridgeType.NONE, BridgeType.OBFS4, BridgeType.MEEK),
            Bridges.autoOrder(BridgeType.SNOWFLAKE))
    }

    @Test
    fun stallWatchOnlyFiresWhenNothingMoves() {
        var clock = 0L
        val watch = StallWatch(30_000) { clock }
        assertFalse(watch.stalled(10))
        clock = 29_000
        assertFalse(watch.stalled(10))
        clock = 30_000
        assertTrue(watch.stalled(10)) // stuck at 10% for 30 seconds: the classic blocked network

        watch.reset()
        clock = 40_000
        assertFalse(watch.stalled(10))
        clock = 60_000
        assertFalse(watch.stalled(45)) // slow but moving is fine
        clock = 85_000
        assertFalse(watch.stalled(50))
        clock = 200_000
        assertFalse(watch.stalled(100)) // finished is never stuck
    }
}
