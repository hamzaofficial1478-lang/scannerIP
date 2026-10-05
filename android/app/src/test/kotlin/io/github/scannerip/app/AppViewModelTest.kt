package io.github.scannerip.app

import android.content.Context
import android.os.Looper
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ApplicationProvider
import io.github.scannerip.core.Level
import io.github.scannerip.core.SAMPLES
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Drives the real ViewModel in demo mode. Robolectric has no Android Keystore,
 * so this also exercises the fallback to a private key file.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AppViewModelTest {
    private lateinit var vm: AppViewModel
    private val store = ViewModelStore()
    private val app get() = ApplicationProvider.getApplicationContext<ScannerIpApplication>()

    private fun waitFor(seconds: Double = 8.0, condition: () -> Boolean) {
        val end = System.nanoTime() + (seconds * 1e9).toLong()
        while (!condition() && System.nanoTime() < end) {
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(20)
        }
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("timed out waiting; shield=${vm.shield.value.state} ${vm.shield.value.status} " +
            "shifts=${vm.shield.value.history.size} history=${vm.history.value.size} layers=${vm.layers.value.size}", condition())
    }

    @Before
    fun setUp() {
        app.getSharedPreferences("settings", Context.MODE_PRIVATE).edit()
            .putString("mode", ShieldMode.DEMO.name)
            .putInt("interval_DEMO", ShieldMode.DEMO.minInterval) // shift every 2 seconds
            .commit()
        // No real GitHub in tests: point update checks at a port nothing listens on.
        app.useUpdater(AppUpdater(app, "http://127.0.0.1:9/", 1, "1.0-test"))
        // A fresh factory: getInstance() caches one tied to the first test's Application.
        vm = ViewModelProvider(store, ViewModelProvider.AndroidViewModelFactory(app))[AppViewModel::class.java]
    }

    @After
    fun tearDown() {
        store.clear() // runs onCleared(), like Android does when the screen goes away
    }

    @Test
    fun demoModeShiftsIpAndIdTogether() {
        waitFor { vm.shield.value.history.size >= 2 && vm.layers.value.isNotEmpty() }
        val state = vm.shield.value
        assertEquals(ShieldState.DEMO, state.state)
        assertTrue(!state.canInspect) // a made-up IP can't hide anything
        val ips = state.history.map { it.exit.ip }
        assertTrue(ips.all { ip -> listOf("192.0.2.", "198.51.100.", "203.0.113.").any(ip::startsWith) })
        assertEquals(state.history.size, state.history.map { it.identity.rotatingId }.toSet().size)
        assertTrue(vm.layers.value[4].value.startsWith("RID-"))
    }

    @Test
    fun checkingASampleLogsItUnderTheRotatingId() {
        waitFor { vm.shield.value.current != null }
        val apk = SAMPLES.first { it.name == "Fake app download" }
        vm.checkText(apk.text, "Demo code")
        waitFor { vm.history.value.isNotEmpty() }
        val result = vm.lastScan.value!!
        assertEquals(Level.DANGEROUS, result.report.level)
        assertEquals("https://free-updates.example/whatsapp-gold.apk", result.inspectableUrl)
        val entry = vm.history.value.first()
        assertEquals("DANGEROUS", entry.level)
        assertTrue(entry.rotatingId!!.startsWith("RID-"))
        assertTrue(vm.historyAsText().contains("whatsapp-gold.apk"))
    }

    @Test
    fun inspectingInDemoModeIsRefused() {
        waitFor { vm.shield.value.current != null }
        vm.inspect("https://bit.ly/x")
        assertEquals(InspectUi.Idle, vm.inspection.value)
    }

    @Test
    fun cameraDoesNotRepeatTheSameCode() {
        waitFor { vm.shield.value.current != null }
        val code = io.github.scannerip.core.Decoded("QR Code", "https://www.bbc.co.uk/news", ByteArray(0), false)
        repeat(30) { vm.onCameraCodes(listOf(code)) } // a second of frames with the same code
        waitFor { vm.history.value.isNotEmpty() }
        Thread.sleep(200)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, vm.history.value.size)
        assertTrue(vm.codesInView.value)
        vm.onCameraCodes(emptyList())
        assertTrue(!vm.codesInView.value)
    }

    @Test
    fun emptyProxyListIsAnError() {
        waitFor { vm.shield.value.current != null }
        vm.setProxyText("")
        vm.setMode(ShieldMode.PROXY_LIST)
        waitFor { vm.shield.value.state == ShieldState.ERROR }
        assertTrue(vm.shield.value.status.contains("empty"))
    }

    @Test
    fun intervalIsClampedAndRemembered() {
        vm.setInterval(1)
        assertEquals(ShieldMode.DEMO.minInterval, vm.shield.value.intervalSeconds)
        vm.setInterval(999)
        assertEquals(AppViewModel.MAX_INTERVAL, vm.shield.value.intervalSeconds)
        assertEquals(AppViewModel.MAX_INTERVAL, app.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getInt("interval_DEMO", -1))
    }

    @Test
    fun keyStorageIsDescribed() {
        waitFor { vm.layers.value.isNotEmpty() }
        assertTrue(vm.keyDescription.isNotEmpty())
    }
}
