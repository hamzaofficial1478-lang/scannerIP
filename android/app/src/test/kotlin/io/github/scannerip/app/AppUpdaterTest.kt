package io.github.scannerip.app

import android.Manifest
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageInstaller
import androidx.test.core.app.ApplicationProvider
import androidx.work.ListenableWorker
import androidx.work.testing.TestListenableWorkerBuilder
import io.github.scannerip.core.UpdateInfo
import io.github.scannerip.core.Updates
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.security.MessageDigest

/** The updater against a pretend GitHub release. (The final install step needs a real phone.) */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AppUpdaterTest {
    private val app get() = ApplicationProvider.getApplicationContext<ScannerIpApplication>()
    private lateinit var web: MockWebServer
    private var apk = ByteArray(50_000) { (it % 97).toByte() } // not a real app
    private var published = 0

    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun info(code: Int = published) = UpdateInfo(code, "1.0.$code", sha(apk), "Faster scanning")
    private fun updater(installed: Int = 4) = AppUpdater(app, web.url("/latest/").toString(), installed, "1.0.$installed")

    @Before
    fun setUp() {
        published = 7
        web = MockWebServer()
        web.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = when (request.path) {
                "/latest/version.json" -> MockResponse().setBody(Updates.encode(info()))
                "/latest/ScannerIP.apk" -> MockResponse().setBody(Buffer().write(apk))
                else -> MockResponse().setResponseCode(404)
            }
        }
        web.start()
    }

    @After
    fun tearDown() = web.shutdown()

    @Test
    fun findsANewerBuildAndRemembersIt() = runBlocking {
        val updater = updater(installed = 4)
        updater.check(null)
        assertEquals(UpdateState.Available(info()), updater.state.value)
        // A fresh start shows it straight away, without asking GitHub again.
        assertEquals(UpdateState.Available(info()), updater(installed = 4).state.value)
    }

    @Test
    fun saysUpToDateWhenNothingIsNewer() = runBlocking {
        val updater = updater(installed = 7)
        updater.check(null)
        assertEquals(UpdateState.UpToDate, updater.state.value)
        assertEquals(UpdateState.Idle, updater(installed = 7).state.value)
    }

    @Test
    fun aBrokenCheckIsReportedNotThrown() = runBlocking {
        val updater = AppUpdater(app, web.url("/nowhere/").toString(), 4, "1.0.4")
        updater.check(null)
        assertTrue((updater.state.value as UpdateState.Failed).message.startsWith("Couldn't check"))
    }

    @Test
    fun refusesADownloadThatIsNotAnApp() = runBlocking {
        val updater = updater()
        updater.check(null)
        updater.downloadAndInstall(null)
        val failed = updater.state.value as UpdateState.Failed
        assertEquals("isn't a valid Android app", true, "valid Android app" in failed.message)
        assertEquals(info(), failed.info) // so "Try again" still knows what to fetch
    }

    @Test
    fun refusesADownloadWithTheWrongFingerprint() = runBlocking {
        val updater = updater()
        updater.check(null)
        apk = ByteArray(50_000) { 1 } // the file changed after version.json was published
        updater.downloadAndInstall(null)
        assertTrue("fingerprint" in (updater.state.value as UpdateState.Failed).message)
    }

    @Test
    fun notifiesOncePerBuild() {
        val updater = updater()
        assertTrue(updater.shouldNotify(info(7)))
        assertFalse(updater.shouldNotify(info(7)))
        assertTrue(updater.shouldNotify(info(8)))
        assertFalse(updater.shouldNotify(info(3))) // older than what's installed
    }

    @Test
    fun backgroundCheckPostsANotification() {
        shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)
        app.useUpdater(updater())
        val result = runBlocking { TestListenableWorkerBuilder<UpdateWorker>(app).build().doWork() }
        assertEquals(ListenableWorker.Result.success(), result)
        val posted = shadowOf(app.getSystemService(NotificationManager::class.java)).allNotifications
        assertEquals(1, posted.size)
        assertEquals("ScannerIP 1.0.7 is ready", shadowOf(posted.single()).contentTitle)
        // Running again for the same build stays quiet.
        runBlocking { TestListenableWorkerBuilder<UpdateWorker>(app).build().doWork() }
        assertEquals(1, shadowOf(app.getSystemService(NotificationManager::class.java)).allNotifications.size)
    }

    @Test
    fun installPromptWaitsBehindANotificationWhenTheAppIsInTheBackground() {
        shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)
        app.useUpdater(updater())
        val confirm = Intent("android.content.pm.action.CONFIRM_INSTALL")
        InstallResultReceiver().onReceive(app, Intent()
            .putExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_PENDING_USER_ACTION)
            .putExtra(Intent.EXTRA_INTENT, confirm))
        val posted = shadowOf(app.getSystemService(NotificationManager::class.java)).allNotifications
        assertEquals("Tap to finish updating ScannerIP", shadowOf(posted.single()).contentTitle)
        assertEquals(null, shadowOf(app).nextStartedActivity) // nothing popped up behind your back
    }

    @Test
    fun aRefusedInstallIsReported() {
        val updater = updater()
        app.useUpdater(updater)
        InstallResultReceiver().onReceive(app, Intent()
            .putExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE_CONFLICT)
            .putExtra(PackageInstaller.EXTRA_STATUS_MESSAGE, "signatures do not match"))
        val failed = updater.state.value as UpdateState.Failed
        assertTrue("signatures do not match" in failed.message)
    }

    @Test
    fun backgroundCheckCanBeSwitchedOff() {
        shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)
        val updater = updater()
        app.useUpdater(updater)
        try {
            updater.setBackgroundChecks(false)
        } catch (_: IllegalStateException) {
            // no WorkManager in this test; the setting itself is what matters here
        }
        runBlocking { TestListenableWorkerBuilder<UpdateWorker>(app).build().doWork() }
        assertEquals(0, shadowOf(app.getSystemService(NotificationManager::class.java)).allNotifications.size)
        assertEquals(0, web.requestCount)
    }
}
