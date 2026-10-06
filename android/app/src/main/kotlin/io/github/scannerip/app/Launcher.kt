package io.github.scannerip.app

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.provider.CalendarContract
import android.provider.ContactsContract
import android.provider.Settings
import androidx.annotation.RequiresApi
import androidx.core.net.toUri
import io.github.scannerip.core.Proceed
import io.github.scannerip.core.WifiSecurity

/**
 * Hands a code over to the phone app that deals with it: the dialler,
 * Contacts, Calendar, Wi-Fi settings and so on.
 *
 * Links with an unknown scheme (whatsapp:, market: and so on) are opened as
 * "browsable", the same rule a web browser follows, so a code can only reach
 * the parts of other apps that are meant to be opened from the web.
 */
object Launcher {
    /** Do it. Returns a message to show, or null if there's nothing to say. */
    fun launch(context: Context, action: Proceed): String? = try {
        when (action) {
            is Proceed.JoinWifi -> joinWifi(context, action)
            is Proceed.Browse -> start(context, browsable(action.url))
            is Proceed.CopyOnly -> action.reason
            else -> start(context, intentFor(action) ?: return null)
        }
    } catch (_: ActivityNotFoundException) {
        "There's no app on this phone that can do that."
    } catch (e: SecurityException) {
        "Android wouldn't let ScannerIP do that: ${e.message}"
    }

    /**
     * Open the page where the advertising ID can be reset or deleted. It
     * lives in Google Play services; failing that, the privacy settings.
     */
    fun openAdSettings(context: Context): String? {
        val pages = buildList {
            add(Intent("com.google.android.gms.settings.ADS_PRIVACY"))
            if (Build.VERSION.SDK_INT >= 29) add(Intent(Settings.ACTION_PRIVACY_SETTINGS))
            add(Intent(Settings.ACTION_SETTINGS))
        }
        for (page in pages) {
            try {
                return start(context, page)
            } catch (_: ActivityNotFoundException) {
                // try the next one
            }
        }
        return "Couldn't open the settings. Look under Settings > Privacy > Ads (or Google > Ads)."
    }

    /** Open a web link in the phone's normal browser, outside the shield. */
    fun openInBrowser(context: Context, url: String): String? = launch(context, Proceed.Browse(url))

    /** The intent for everything except Wi-Fi, which needs more care. Visible for tests. */
    fun intentFor(action: Proceed): Intent? = when (action) {
        is Proceed.Call -> Intent(Intent.ACTION_DIAL, Uri.fromParts("tel", action.number, null))
        is Proceed.Text -> Intent(Intent.ACTION_SENDTO, Uri.fromParts("smsto", action.number, null))
            .putExtra("sms_body", action.body)
        is Proceed.Email -> Intent(Intent.ACTION_SENDTO, "mailto:".toUri())
            .putExtra(Intent.EXTRA_EMAIL, arrayOf(action.to))
            .putExtra(Intent.EXTRA_SUBJECT, action.subject)
            .putExtra(Intent.EXTRA_TEXT, action.body)
        is Proceed.AddContact -> contact(action)
        is Proceed.AddEvent -> Intent(Intent.ACTION_INSERT, CalendarContract.Events.CONTENT_URI).apply {
            putExtra(CalendarContract.Events.TITLE, action.title)
            action.startMillis?.let { putExtra(CalendarContract.EXTRA_EVENT_BEGIN_TIME, it) }
            action.endMillis?.let { putExtra(CalendarContract.EXTRA_EVENT_END_TIME, it) }
            putExtra(CalendarContract.EXTRA_EVENT_ALL_DAY, action.allDay)
            putExtra(CalendarContract.Events.EVENT_LOCATION, action.location)
            putExtra(CalendarContract.Events.DESCRIPTION, action.description)
        }
        // geo:, otpauth: and the payment schemes are a fixed list, so any app that handles them will do.
        is Proceed.ShowOnMap -> Intent(Intent.ACTION_VIEW, action.uri.toUri())
        is Proceed.AddAuthenticator -> Intent(Intent.ACTION_VIEW, action.uri.toUri())
        is Proceed.Pay -> Intent(Intent.ACTION_VIEW, action.uri.toUri())
        is Proceed.OpenApp -> browsable(action.uri)
        is Proceed.Browse -> browsable(action.url)
        is Proceed.JoinWifi, is Proceed.CopyOnly -> null
    }

    private fun browsable(uri: String) = Intent(Intent.ACTION_VIEW, uri.toUri()).addCategory(Intent.CATEGORY_BROWSABLE)

    private fun contact(action: Proceed.AddContact): Intent {
        val card = action.card
        val intent = Intent(ContactsContract.Intents.Insert.ACTION).setType(ContactsContract.RawContacts.CONTENT_TYPE)
        intent.putExtra(ContactsContract.Intents.Insert.NAME, card.name)
        val phoneKeys = listOf(ContactsContract.Intents.Insert.PHONE, ContactsContract.Intents.Insert.SECONDARY_PHONE,
            ContactsContract.Intents.Insert.TERTIARY_PHONE)
        card.phones.zip(phoneKeys).forEach { (number, key) -> intent.putExtra(key, number) }
        val emailKeys = listOf(ContactsContract.Intents.Insert.EMAIL, ContactsContract.Intents.Insert.SECONDARY_EMAIL,
            ContactsContract.Intents.Insert.TERTIARY_EMAIL)
        card.emails.zip(emailKeys).forEach { (email, key) -> intent.putExtra(key, email) }
        if (card.organisation.isNotEmpty()) intent.putExtra(ContactsContract.Intents.Insert.COMPANY, card.organisation)
        if (card.jobTitle.isNotEmpty()) intent.putExtra(ContactsContract.Intents.Insert.JOB_TITLE, card.jobTitle)
        if (card.address.isNotEmpty()) intent.putExtra(ContactsContract.Intents.Insert.POSTAL, card.address)
        if (card.note.isNotEmpty()) intent.putExtra(ContactsContract.Intents.Insert.NOTES, card.note)
        if (card.website.isNotEmpty()) {
            val row = ContentValues().apply {
                put(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Website.CONTENT_ITEM_TYPE)
                put(ContactsContract.CommonDataKinds.Website.URL, card.website)
            }
            intent.putParcelableArrayListExtra(ContactsContract.Intents.Insert.DATA, arrayListOf(row))
        }
        return intent
    }

    private fun joinWifi(context: Context, wifi: Proceed.JoinWifi): String? {
        if (Build.VERSION.SDK_INT >= 30) {
            suggestion(wifi)?.let { suggestion ->
                // Android shows its own "Save this network?" sheet; nothing joins without you.
                context.startActivity(Intent(Settings.ACTION_WIFI_ADD_NETWORKS)
                    .putParcelableArrayListExtra(Settings.EXTRA_WIFI_NETWORK_LIST, arrayListOf(suggestion))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return null
            }
        }
        // Older phones (and old WEP networks) can't be handed a network, so do the next best thing.
        if (wifi.password.isNotEmpty()) {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("Wi-Fi password", wifi.password))
        }
        context.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        return if (wifi.password.isEmpty()) "Pick \"${wifi.ssid}\" in the list. It has no password, so anyone nearby can see what you send."
        else "Password copied. Pick \"${wifi.ssid}\" in the list and paste it in."
    }

    @RequiresApi(30)
    private fun suggestion(wifi: Proceed.JoinWifi): WifiNetworkSuggestion? = try {
        WifiNetworkSuggestion.Builder().setSsid(wifi.ssid).setIsHiddenSsid(wifi.hidden).apply {
            when (wifi.security) {
                WifiSecurity.OPEN -> {}
                WifiSecurity.WPA -> setWpa2Passphrase(wifi.password)
                WifiSecurity.WPA3 -> setWpa3Passphrase(wifi.password)
                WifiSecurity.WEP, WifiSecurity.ENTERPRISE -> return null
            }
        }.build()
    } catch (_: IllegalArgumentException) {
        null // a password Android won't accept (too short, say): fall back to settings
    }

    private fun start(context: Context, intent: Intent): String? {
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        return null
    }
}
