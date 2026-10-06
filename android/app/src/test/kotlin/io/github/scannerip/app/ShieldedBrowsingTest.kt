package io.github.scannerip.app

import android.content.Context
import android.os.Looper
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ApplicationProvider
import io.github.scannerip.core.ExitLookup
import io.github.scannerip.core.Net
import io.github.scannerip.core.Route
import okhttp3.Request
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.DataInputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * The whole path a link takes when you tap "Open safely": the ViewModel shifts
 * to a fresh IP and ID, holds the timer, starts the relay, and the browser's
 * traffic comes out of the shield's proxy with the shield's login.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ShieldedBrowsingTest {
    private val store = ViewModelStore()
    private val app get() = ApplicationProvider.getApplicationContext<ScannerIpApplication>()
    private lateinit var vm: AppViewModel

    // A stand-in for the proxy: speaks SOCKS5, notes who asked for what, serves a two-byte page.
    private val proxy = ServerSocket(0)
    private val asked = Collections.synchronizedList(mutableListOf<Pair<String?, String>>())
    private val lookups = AtomicInteger()
    @Volatile private var lookupsFail = false

    private fun waitFor(seconds: Double = 8.0, condition: () -> Boolean) {
        val end = System.nanoTime() + (seconds * 1e9).toLong()
        while (!condition() && System.nanoTime() < end) {
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(20)
        }
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("timed out; shield=${vm.shield.value.state} ${vm.shield.value.status} browser=${vm.browser.value}", condition())
    }

    @Before
    fun setUp() {
        thread(isDaemon = true) {
            while (!proxy.isClosed) {
                val client = try { proxy.accept() } catch (_: IOException) { break }
                thread(isDaemon = true) { serve(client) }
            }
        }
        // Each shift "finds" a new exit address without going near the internet.
        app.exitLookup = {
            if (lookupsFail) throw IOException("circuit too slow")
            ExitLookup("185.220.101.${lookups.incrementAndGet()}", true)
        }
        app.useUpdater(AppUpdater(app, "http://127.0.0.1:9/", 1, "1.0-test"))
        app.getSharedPreferences("settings", Context.MODE_PRIVATE).edit()
            .putString("mode", ShieldMode.PROXY_LIST.name)
            .putString("proxies", "socks5://student:pw@127.0.0.1:${proxy.localPort}")
            .putInt("interval_PROXY_LIST", ShieldMode.PROXY_LIST.minInterval)
            .commit()
        vm = ViewModelProvider(store, ViewModelProvider.AndroidViewModelFactory(app))[AppViewModel::class.java]
    }

    @After
    fun tearDown() {
        store.clear()
        proxy.close()
        app.exitLookup = null
    }

    private fun serve(client: Socket) = client.use {
        val input = DataInputStream(client.getInputStream())
        val output = client.getOutputStream()
        input.readUnsignedByte()
        val methods = ByteArray(input.readUnsignedByte()).also(input::readFully)
        var user: String? = null
        if (2.toByte() in methods) {
            output.write(byteArrayOf(5, 2))
            input.readUnsignedByte()
            user = String(ByteArray(input.readUnsignedByte()).also(input::readFully))
            ByteArray(input.readUnsignedByte()).also(input::readFully)
            output.write(byteArrayOf(1, 0))
        } else {
            output.write(byteArrayOf(5, 0))
        }
        input.readUnsignedByte(); input.readUnsignedByte(); input.readUnsignedByte()
        check(input.readUnsignedByte() == 3) { "the site's name should arrive unresolved" }
        val host = String(ByteArray(input.readUnsignedByte()).also(input::readFully))
        input.readUnsignedShort()
        asked += user to host
        output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        val request = StringBuilder()
        while (!request.endsWith("\r\n\r\n")) request.append(input.readUnsignedByte().toChar())
        output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi".toByteArray())
        output.flush()
    }

    private fun fetchThroughBrowserPort(port: Int, url: String): String =
        Net.client(Route.Socks("127.0.0.1", port)).newCall(Request.Builder().url(url).build()).execute()
            .use { it.body!!.string() }

    @Test
    fun openSafelyShiftsHoldsAndRoutesThroughTheShield() {
        waitFor { vm.shield.value.state == ShieldState.ACTIVE }
        val before = vm.shield.value.current!!

        vm.openShielded("http://quiz.invalid/start")
        waitFor { vm.browser.value?.ready == true }
        val page = vm.browser.value!!
        val now = vm.shield.value.current!!
        // A fresh shift just for this page, and the bar shows exactly that address and ID.
        assertNotEquals(before.identity.rotatingId, now.identity.rotatingId)
        assertEquals(now.exit.ip, page.exitIp)
        assertEquals(now.identity.rotatingId, page.rotatingId)
        assertTrue(vm.shield.value.paused)
        // The timer (every 3 seconds in this mode) is on hold while the page is open.
        val held = vm.shield.value.history.size
        Thread.sleep(3600)
        assertEquals(held, vm.shield.value.history.size)

        // What the WebView will do: plain SOCKS to the relay. It comes out with the shield's login.
        assertEquals("hi", fetchThroughBrowserPort(page.proxyPort, "http://quiz.invalid/start"))
        assertEquals("student" to "quiz.invalid", asked.last())

        // New IP: another shift, a new session (so cookies get wiped) and the page the user was on.
        vm.newBrowserIdentity("http://quiz.invalid/page2")
        waitFor { vm.browser.value?.ready == true && vm.browser.value?.session != page.session }
        val again = vm.browser.value!!
        assertEquals("http://quiz.invalid/page2", again.url)
        assertNotEquals(page.exitIp, again.exitIp)
        assertEquals(page.proxyPort, again.proxyPort)

        // Closing ends the relay and gets the timer going again.
        val shifts = vm.shield.value.history.size
        vm.closeBrowser()
        assertNull(vm.browser.value)
        assertFalse(vm.shield.value.paused)
        val stillOpen = try { Socket("127.0.0.1", page.proxyPort).close(); true } catch (_: IOException) { false }
        assertFalse("the relay should stop listening once the browser closes", stillOpen)
        waitFor { vm.shield.value.history.size > shifts }
    }

    @Test
    fun closingStraightAwayLeavesNothingBehind() {
        waitFor { vm.shield.value.state == ShieldState.ACTIVE }
        vm.openShielded("http://quiz.invalid/")
        vm.closeBrowser() // before the fresh IP has even arrived
        Thread.sleep(500)
        shadowOf(Looper.getMainLooper()).idle()
        assertNull(vm.browser.value)
        assertFalse(vm.shield.value.paused)
        // The shift that was in flight, the one on resuming, then the timer's own: it's running again.
        val shifts = vm.shield.value.history.size
        waitFor(10.0) { vm.shield.value.history.size >= shifts + 3 }
        assertFalse("no relay should be left listening",
            Thread.getAllStackTraces().keys.any { it.name == "socks-relay" && it.isAlive })
    }

    @Test
    fun aSlowShiftKeepsTheShieldOnAndOnlyARunOfFailuresTurnsItRed() {
        waitFor { vm.shield.value.state == ShieldState.ACTIVE }
        val ip = vm.shield.value.current!!.exit.ip
        lookupsFail = true
        waitFor { "didn't finish" in vm.shield.value.status }
        // Still protected, on the address it had: the proxy behind it hasn't gone anywhere.
        assertEquals(ShieldState.ACTIVE, vm.shield.value.state)
        assertEquals(ip, vm.shield.value.current!!.exit.ip)
        assertTrue(vm.shield.value.canInspect)
        // Three in a row is a real problem, and says so.
        waitFor(15.0) { vm.shield.value.state == ShieldState.ERROR }
        assertTrue("in a row" in vm.shield.value.status)
        // And it recovers on its own once shifts work again.
        lookupsFail = false
        waitFor(15.0) { vm.shield.value.state == ShieldState.ACTIVE && vm.shield.value.current!!.exit.ip != ip }
    }

    @Test
    fun noShiftingWhileTheAppIsOffScreen() {
        waitFor { vm.shield.value.state == ShieldState.ACTIVE }
        vm.appVisible(false)
        Thread.sleep(300) // let a shift that was already under way finish
        val before = vm.shield.value.history.size
        Thread.sleep(3600) // longer than the 3-second interval
        assertEquals(before, vm.shield.value.history.size)
        vm.appVisible(true) // back on screen: a fresh shift straight away
        waitFor(2.0) { vm.shield.value.history.size > before }
    }

    @Test
    fun handingOffToAnotherAppStillMovesTheId() {
        waitFor { vm.shield.value.state == ShieldState.ACTIVE }
        val id = vm.shield.value.current!!.identity.rotatingId
        vm.proceededElsewhere()
        waitFor { vm.shield.value.current!!.identity.rotatingId != id }
    }
}
