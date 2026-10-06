package io.github.scannerip.app.ui

import android.graphics.Bitmap
import android.content.Context
import android.graphics.Canvas
import androidx.activity.ComponentActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ApplicationProvider
import io.github.scannerip.app.AppViewModel
import io.github.scannerip.app.ScannerIpApplication
import io.github.scannerip.core.SAMPLES
import io.github.scannerip.app.ScanResult
import io.github.scannerip.app.ShieldMode
import io.github.scannerip.app.ShieldState
import io.github.scannerip.app.ShieldUi
import io.github.scannerip.core.IdentityVault
import io.github.scannerip.core.ScanLog
import io.github.scannerip.core.Shield
import io.github.scannerip.core.SimulatedRotator
import io.github.scannerip.core.SoftwareKeys
import io.github.scannerip.core.analyseText
import androidx.compose.ui.unit.dp
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/**
 * Renders every screen on the JVM (no phone or emulator needed) and saves a
 * PNG of each to app/build/screenshots, so the layout can be checked by eye.
 * The asserts double as smoke tests that each screen shows what it should.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w411dp-h891dp-xxhdpi")
class ScreenshotTest {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private val vault = IdentityVault(SoftwareKeys(ByteArray(32) { 3 }), "demo phone".toByteArray())
    private val shield = Shield(SimulatedRotator(seed = 11), vault).also { s -> repeat(4) { s.rotateNow() } }

    private fun shieldUi(state: ShieldState = ShieldState.ACTIVE, mode: ShieldMode = ShieldMode.BUILT_IN_TOR) = ShieldUi(
        mode = mode,
        state = state,
        status = if (state == ShieldState.ACTIVE) "Protected via Tor circuit #4 - Tor confirmed" else "Starting Tor 45% - Loading relay descriptors",
        torProgress = if (state == ShieldState.STARTING) 45 else null,
        current = shield.current?.let { it.copy(exit = it.exit.copy(ip = "185.220.101.42", via = "Tor circuit #4", isTor = true)) },
        history = shield.history.reversed(),
        secondsLeft = 17,
        intervalSeconds = 30,
    )

    private fun result(text: String, format: String = "QR Code") =
        ScanResult(1, format, analyseText(text), null, shield.current?.identity?.rotatingId)

    private fun shoot(name: String, dark: Boolean = false, content: @Composable () -> Unit) {
        compose.setContent {
            ScannerIpTheme(dark = dark) { Surface { Column { content() } } }
        }
        compose.waitForIdle()
        // Draw the window straight into a bitmap (captureToImage waits for a frame
        // callback that Robolectric's paused looper never delivers).
        val view = compose.activity.window.decorView.rootView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        view.draw(Canvas(bitmap))
        val dir = File("build/screenshots").apply { mkdirs() }
        File(dir, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Composable
    private fun FakeCamera(modifier: Modifier) {
        Box(modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF2B3A35), Color(0xFF0E1412)))),
            contentAlignment = Alignment.Center) {
            Text("(camera preview)", color = Color(0x88FFFFFF))
        }
    }

    @Test
    fun scanScreenWithADangerousResult() {
        shoot("1-scan") {
            TopBarPreview(shieldUi())
            ScanScreen(
                hasCameraPermission = true, codesInView = true, torchOn = false,
                lastScan = result("https://paypal.com@login-verify.example/secure/update"),
                canInspect = true, inspecting = false,
                onAskPermission = {}, onPickImage = {}, onToggleTorch = {}, onInspect = {}, onCopy = {},
                camera = { FakeCamera(it) },
            )
        }
        compose.onNodeWithText("Check where it goes").assertExists()
        compose.onNodeWithText("HIGH  55/100").assertExists()
    }

    @Test
    fun scanScreenAskingForTheCamera() {
        shoot("1b-scan-permission") {
            ScanScreen(
                hasCameraPermission = false, codesInView = false, torchOn = false, lastScan = null,
                canInspect = false, inspecting = false,
                onAskPermission = {}, onPickImage = {}, onToggleTorch = {}, onInspect = {}, onCopy = {},
                camera = { FakeCamera(it) },
            )
        }
        compose.onNodeWithText("Allow camera").assertExists()
    }

    @Test
    fun checkScreenWithAnApkLink() {
        shoot("2-check") {
            CheckScreen(
                lastScan = result("https://free-updates.example/whatsapp-gold.apk", "Typed in"),
                canInspect = false, inspecting = false,
                onCheck = {}, onSample = {}, onInspect = {}, onCopy = {},
            )
        }
        compose.onNodeWithText("DANGEROUS  90/100").assertExists()
    }

    @Test
    fun shieldScreenActive() {
        shoot("3-shield") {
            ShieldScreen(shieldUi(), {}, {}, {}, {}, {}, {}, {})
        }
        compose.onNodeWithText("185.220.101.42").assertExists()
    }

    @Test
    fun shieldScreenWhileTorStarts() {
        shoot("3b-shield-starting") {
            ShieldScreen(shieldUi(ShieldState.STARTING).copy(current = null, history = emptyList()), {}, {}, {}, {}, {}, {}, {})
        }
        compose.onNodeWithText("Connecting").assertExists()
    }

    @Test
    fun shieldScreenInDarkMode() {
        shoot("3c-shield-dark", dark = true) {
            ShieldScreen(shieldUi(), {}, {}, {}, {}, {}, {}, {})
        }
        compose.onNodeWithText("Shield on").assertExists()
    }

    @Test
    fun updateBannerAndCard() {
        val info = io.github.scannerip.core.UpdateInfo(12, "1.0.12", "a".repeat(64), "Faster scanning and a clearer Shield tab")
        shoot("6-updates") {
            UpdateBanner(io.github.scannerip.app.UpdateState.Available(info), onUpdate = {})
            UpdateBanner(io.github.scannerip.app.UpdateState.Downloading(info, 0.45f), onUpdate = {})
            Column(Modifier.padding(16.dp)) {
                UpdatesCard("1.0.5", io.github.scannerip.app.UpdateState.Available(info), backgroundChecks = true,
                    onCheck = {}, onBackgroundChecks = {})
            }
        }
        compose.onNodeWithText("Update now").assertExists()
        compose.onNodeWithText("Downloading 45% through the shield...").assertExists()
        compose.onNodeWithText("You have ScannerIP 1.0.5").assertExists()
    }

    @Test
    fun proceedButtonsForEachKindOfCode() {
        shoot("7-proceed") {
            Column(Modifier.padding(horizontal = 16.dp)) {
                ResultCard(result("WIFI:T:WPA;S:HomeNet;P:correct horse battery staple;;"), true, false, {}, {})
                androidx.compose.foundation.layout.Spacer(Modifier.padding(6.dp))
                ResultCard(result("https://www.bbc.co.uk/news"), true, false, {}, {})
            }
        }
        compose.onNodeWithText("Join network").assertExists()
        compose.onNodeWithText("Open safely").assertExists()
        compose.onNodeWithText("Open in my browser instead").assertExists()
    }

    @Test
    fun riskyCodesAskBeforeGoingAhead() {
        var went = 0
        shoot("7b-proceed-confirm") {
            ResultCard(result("https://free-updates.example/whatsapp-gold.apk"), true, false, {}, {}, onProceed = { went++ })
        }
        compose.onNodeWithText("Open safely").performClick()
        compose.onNodeWithText("This code looks dangerous").assertExists()
        assertEquals(0, went)
        compose.onNodeWithText("Go ahead anyway").performClick()
        assertEquals(1, went)
    }

    @Test
    fun shieldedBrowserBar() {
        val state = io.github.scannerip.app.BrowserUi("https://www.bbc.co.uk/news", "185.220.101.42",
            "RID-7Q2M-K9XD-4HCT-PW3N", proxyPort = 40123)
        shoot("8-browser") {
            BrowserScreen(state, "https://www.bbc.co.uk/news", 60, androidx.compose.material3.SnackbarHostState(), {}, {}) { modifier ->
                Box(modifier.background(Color(0xFFF4F4F4)), contentAlignment = Alignment.Center) {
                    Text("(web page)", color = Color(0x88000000))
                }
            }
        }
        compose.onNodeWithText("Site sees 185.220.101.42").assertExists()
        compose.onNodeWithText("New IP").assertExists()
    }

    @Test
    fun shieldScreenWithBridges() {
        shoot("3d-shield-bridges") {
            ShieldScreen(shieldUi().copy(via = io.github.scannerip.core.BridgeType.SNOWFLAKE), {}, {}, {}, {}, {}, {}, {})
        }
        compose.onNodeWithText("Getting past blocks").assertExists()
        compose.onNodeWithText("Automatic (recommended)").assertExists()
    }

    @Test
    fun idsScreen() {
        shoot("4-ids") {
            IdsScreen(vault.layers(), vault.keyDescription) {}
        }
        compose.onNodeWithText("Layer 4  Rotating ID").assertExists()
    }

    @Test
    fun historyScreen() {
        val log = ScanLog(File.createTempFile("history", ".jsonl").apply { delete() })
        listOf("https://www.bbc.co.uk/news", "WIFI:T:nopass;S:Free Airport WiFi;;", "tel:*%2306%23",
            "https://bit.ly/3xExample").forEach { log.record("QR Code", analyseText(it), shield.rotateNow().identity) }
        shoot("5-history") {
            HistoryScreen(log.readAll().asReversed(), {}, {})
        }
        compose.onNodeWithText("Scan history").assertExists()
    }
}

/** The whole app, wired to the real ViewModel in demo mode, clicking through the tabs. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w411dp-h891dp-xxhdpi")
class FullAppScreenshotTest {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private fun save(name: String) {
        compose.waitForIdle()
        val view = compose.activity.window.decorView.rootView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        view.draw(Canvas(bitmap))
        File(File("build/screenshots").apply { mkdirs() }, "$name.png").outputStream().use {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
        }
    }

    @Test
    fun clickThroughTheApp() {
        val app = ApplicationProvider.getApplicationContext<ScannerIpApplication>()
        app.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().putString("mode", ShieldMode.DEMO.name).commit()
        app.useUpdater(io.github.scannerip.app.AppUpdater(app, "http://127.0.0.1:9/", 1, "1.0-test")) // no real GitHub
        val store = ViewModelStore()
        val vm = ViewModelProvider(store, ViewModelProvider.AndroidViewModelFactory(app))[AppViewModel::class.java]
        compose.setContent { ScannerIpTheme(dark = false) { ScannerIpApp(vm) } }
        compose.waitUntil(10_000) { vm.shield.value.current != null }
        vm.checkText(SAMPLES.first { it.name == "Tampered payment" }.text, "Demo code")
        compose.waitUntil(5_000) { vm.history.value.isNotEmpty() }
        save("0-app-scan")
        compose.onNodeWithText("Allow camera").assertExists()
        compose.onNodeWithText("HIGH  70/100").assertExists()

        compose.onNodeWithText("Shield").performClick()
        save("0-app-shield")
        compose.onNodeWithText("Demo mode - made-up IPs").assertExists()
        compose.onNodeWithText("A made-up address for the demo. Websites still see your real one.").assertExists()

        compose.onNodeWithText("IDs").performClick()
        compose.onNodeWithText("Layer 4  Rotating ID").assertExists()
        compose.onNodeWithText("History").performClick()
        compose.onNodeWithText("Merchant payment").assertExists()
        save("0-app-history")
        store.clear()
    }
}

@Composable
private fun TopBarPreview(state: ShieldUi) {
    androidx.compose.foundation.layout.Row(
        Modifier.background(Color.Transparent),
    ) { ShieldChip(state) }
}
