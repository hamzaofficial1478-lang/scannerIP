package io.github.scannerip.app

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiNetworkSuggestion
import android.provider.CalendarContract
import android.provider.ContactsContract
import android.provider.Settings
import androidx.test.core.app.ApplicationProvider
import io.github.scannerip.core.Proceed
import io.github.scannerip.core.classify
import io.github.scannerip.core.proceedFor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class LauncherTest {
    private val app = ApplicationProvider.getApplicationContext<Context>()

    private fun go(code: String): Pair<String?, Intent?> {
        val message = Launcher.launch(app, proceedFor(classify(code)))
        return message to shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>()).nextStartedActivity
    }

    @Test
    fun callsOnlyFillInTheDialler() {
        val (_, intent) = go("tel:+44 20 7946 0000")
        assertEquals(Intent.ACTION_DIAL, intent!!.action) // never ACTION_CALL: you still press call
        assertEquals("+44 20 7946 0000", intent.data!!.schemeSpecificPart)
        // USSD codes keep their # (encoded), so the dialler shows exactly what was in the code.
        assertEquals("*#06#", Launcher.intentFor(Proceed.Call("*#06#"))!!.data!!.schemeSpecificPart)
    }

    @Test
    fun textsAndEmailsArePrefilled() {
        val (_, sms) = go("SMSTO:84433:WIN PRIZE")
        assertEquals(Intent.ACTION_SENDTO, sms!!.action)
        assertEquals("smsto:84433", sms.data.toString())
        assertEquals("WIN PRIZE", sms.getStringExtra("sms_body"))

        val (_, mail) = go("mailto:a@example.com?subject=Hi&body=Body%20text")
        assertEquals(Intent.ACTION_SENDTO, mail!!.action)
        assertEquals(listOf("a@example.com"), mail.getStringArrayExtra(Intent.EXTRA_EMAIL)!!.toList())
        assertEquals("Hi", mail.getStringExtra(Intent.EXTRA_SUBJECT))
        assertEquals("Body text", mail.getStringExtra(Intent.EXTRA_TEXT))
    }

    @Test
    fun contactsGoToTheContactsApp() {
        val (_, intent) = go("BEGIN:VCARD\nFN:Ayesha Khan\nTEL:0123\nTEL:0456\nEMAIL:a@example.com\nORG:School\n" +
            "URL:https://example.com\nEND:VCARD")
        assertEquals(ContactsContract.Intents.Insert.ACTION, intent!!.action)
        assertEquals("Ayesha Khan", intent.getStringExtra(ContactsContract.Intents.Insert.NAME))
        assertEquals("0123", intent.getStringExtra(ContactsContract.Intents.Insert.PHONE))
        assertEquals("0456", intent.getStringExtra(ContactsContract.Intents.Insert.SECONDARY_PHONE))
        assertEquals("a@example.com", intent.getStringExtra(ContactsContract.Intents.Insert.EMAIL))
        assertEquals("School", intent.getStringExtra(ContactsContract.Intents.Insert.COMPANY))
        assertEquals(1, intent.getParcelableArrayListExtra(ContactsContract.Intents.Insert.DATA,
            android.content.ContentValues::class.java)!!.size)
    }

    @Test
    fun eventsGoToTheCalendar() {
        val (_, intent) = go("BEGIN:VEVENT\nSUMMARY:Science fair\nDTSTART:20261020T090000Z\nDTEND:20261020T120000Z\n" +
            "LOCATION:Hall\nEND:VEVENT")
        assertEquals(Intent.ACTION_INSERT, intent!!.action)
        assertEquals(CalendarContract.Events.CONTENT_URI, intent.data)
        assertEquals("Science fair", intent.getStringExtra(CalendarContract.Events.TITLE))
        assertEquals(1_792_486_800_000L, intent.getLongExtra(CalendarContract.EXTRA_EVENT_BEGIN_TIME, 0))
        assertEquals("Hall", intent.getStringExtra(CalendarContract.Events.EVENT_LOCATION))
    }

    @Test
    fun linksForOtherAppsMustBeBrowsable() {
        // The same rule a browser follows: only parts of apps meant to be opened from the web.
        val (_, app) = go("whatsapp://send?text=hi")
        assertTrue(app!!.hasCategory(Intent.CATEGORY_BROWSABLE))
        assertNull(app.component)
        val (_, web) = Launcher.openInBrowser(this.app, "https://example.com/") to
            shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>()).nextStartedActivity
        assertTrue(web!!.hasCategory(Intent.CATEGORY_BROWSABLE))
        assertEquals("https://example.com/", web.dataString)
        // Fixed schemes go to whichever app handles them.
        val (_, otp) = go("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        assertEquals(Intent.ACTION_VIEW, otp!!.action)
        assertTrue("secret=JBSWY3DPEHPK3PXP" in otp.dataString!!)
    }

    @Test
    fun wifiUsesAndroidsOwnSaveNetworkSheet() {
        val (message, intent) = go("WIFI:T:WPA;S:HomeNet;P:correct horse battery staple;;")
        assertNull(message)
        assertEquals(Settings.ACTION_WIFI_ADD_NETWORKS, intent!!.action)
        val list = intent.getParcelableArrayListExtra(Settings.EXTRA_WIFI_NETWORK_LIST, WifiNetworkSuggestion::class.java)!!
        assertEquals("HomeNet", list.single().ssid)
    }

    @Test
    fun oldWepNetworksFallBackToSettingsWithThePasswordCopied() {
        val (message, intent) = go("WIFI:T:WEP;S:OldCafe;P:abcde;;")
        assertEquals(Settings.ACTION_WIFI_SETTINGS, intent!!.action)
        assertTrue(message!!.contains("Password copied"))
        val clip = (app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).primaryClip!!
        assertEquals("abcde", clip.getItemAt(0).text.toString())
    }

    @Test
    fun codesThatCantBeOpenedSaySoAndStartNothing() {
        val (message, intent) = go("javascript:alert(1)")
        assertTrue(message!!.contains("won't open"))
        assertNull(intent)
    }

    @Test
    fun advertisingIdSettingsOpenGooglesAdsPage() {
        assertNull(Launcher.openAdSettings(app))
        val page = shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>()).nextStartedActivity
        assertEquals("com.google.android.gms.settings.ADS_PRIVACY", page.action)
    }

    @Test
    fun noAppForItIsReportedNotCrashed() {
        shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>()).checkActivities(true)
        val message = Launcher.launch(app, proceedFor(classify("bitcoin:bc1qexample?amount=0.05")))
        assertFalse(message.isNullOrEmpty())
        assertTrue(message!!.contains("no app"))
    }
}
