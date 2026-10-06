package io.github.scannerip.core

import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/*
 * What "go ahead" means for each kind of code.
 *
 * Scanning only reads. Proceeding is the step that actually does something:
 * opening a page, joining a network, saving a contact, starting a payment.
 * This file works out what that something is, without doing it, so the app can
 * show the right button and the tests can check every case without a phone.
 *
 * Only web pages can be kept behind the shield, because ScannerIP opens them
 * in its own browser. Everything else is handed to another app on the phone
 * (the dialler, Contacts, Wi-Fi settings...), and those apps use the phone's
 * normal connection. The app is upfront about that on screen.
 */

enum class WifiSecurity { OPEN, WEP, WPA, WPA3, ENTERPRISE }

data class ContactCard(
    val name: String,
    val phones: List<String>,
    val emails: List<String>,
    val organisation: String,
    val jobTitle: String,
    val address: String,
    val website: String,
    val note: String,
)

sealed class Proceed(val button: String) {
    /** True when the action stays inside ScannerIP, behind the shield. */
    open val shielded: Boolean get() = false

    /** A web page, opened in ScannerIP's own browser through the shield. */
    data class Browse(val url: String) : Proceed("Open safely") {
        override val shielded get() = true
    }

    data class JoinWifi(val ssid: String, val password: String, val security: WifiSecurity, val hidden: Boolean) :
        Proceed("Join network")

    data class AddContact(val card: ContactCard) : Proceed("Add contact")

    /** Fills in the dialler. Android still waits for you to press call. */
    data class Call(val number: String) : Proceed("Call")

    data class Text(val number: String, val body: String) : Proceed("Write text")

    data class Email(val to: String, val subject: String, val body: String) : Proceed("Write email")

    data class ShowOnMap(val uri: String) : Proceed("Open map")

    data class AddEvent(
        val title: String,
        val startMillis: Long?,
        val endMillis: Long?,
        val allDay: Boolean,
        val location: String,
        val description: String,
    ) : Proceed("Add to calendar")

    /** The full otpauth:// link, secret included, straight to an authenticator app. */
    data class AddAuthenticator(val uri: String) : Proceed("Add to authenticator")

    data class Pay(val uri: String, val what: String) : Proceed("Pay with app")

    /** A link meant for another app (WhatsApp, the Play Store...). */
    data class OpenApp(val uri: String, val scheme: String) : Proceed("Open in app")

    /** Nothing sensible (or safe) to do apart from copying it. */
    data class CopyOnly(val reason: String) : Proceed("")
}

// Link types that can run code or reach inside other apps. These never get a button.
private val NEVER_OPEN = setOf(
    "javascript", "vbscript", "data", "file", "intent", "content", "blob", "about",
    "itms-services", "itms-apps", "jar", "chrome", "android-app",
)

/** Work out what proceeding with [payload] should do. */
fun proceedFor(payload: Payload): Proceed {
    val f = payload.fields
    return when (payload.kind) {
        Kind.URL -> {
            val url = f["url"] ?: payload.raw.trim()
            when (val scheme = f["scheme"]?.lowercase() ?: "") {
                "http", "https" -> Proceed.Browse(url)
                in NEVER_OPEN -> Proceed.CopyOnly(
                    "Links starting with \"$scheme:\" can run code or reach into other apps, so ScannerIP won't open them.")
                else -> Proceed.OpenApp(url, scheme)
            }
        }
        Kind.WIFI -> {
            val security = when (f["T"]?.trim()?.uppercase()) {
                null, "", "NOPASS", "NONE" -> WifiSecurity.OPEN
                "WEP" -> WifiSecurity.WEP
                "SAE", "WPA3" -> WifiSecurity.WPA3
                "WPA2-EAP", "WPA-EAP", "EAP", "WPA3-EAP" -> WifiSecurity.ENTERPRISE
                else -> WifiSecurity.WPA
            }
            val ssid = f["S"].orEmpty()
            when {
                ssid.isEmpty() -> Proceed.CopyOnly("This Wi-Fi code has no network name in it.")
                security == WifiSecurity.ENTERPRISE -> Proceed.CopyOnly(
                    "Work and university Wi-Fi needs your own login, so set it up in Wi-Fi settings.")
                else -> Proceed.JoinWifi(ssid, f["P"].orEmpty(), security, f["H"].equals("true", ignoreCase = true))
            }
        }
        Kind.CONTACT -> Proceed.AddContact(contactCard(f))
        Kind.PHONE -> f["number"]?.ifBlank { null }?.let { Proceed.Call(it) }
            ?: Proceed.CopyOnly("There's no number in it.")
        Kind.SMS -> f["number"]?.ifBlank { null }?.let { Proceed.Text(it, f["body"].orEmpty()) }
            ?: Proceed.CopyOnly("There's no number in it.")
        Kind.EMAIL -> Proceed.Email(f["to"].orEmpty(), f["subject"].orEmpty(), f["body"].orEmpty())
        Kind.GEO -> Proceed.ShowOnMap(payload.raw.trim())
        Kind.CALENDAR -> calendarEvent(f)
        Kind.OTP -> Proceed.AddAuthenticator(payload.raw.trim())
        Kind.CRYPTO -> Proceed.Pay(payload.raw.trim(), f["coin"] ?: "crypto")
        Kind.PAYMENT -> if (f["scheme"] == "UPI") {
            Proceed.Pay(payload.raw.trim(), "UPI")
        } else {
            Proceed.CopyOnly("Merchant codes like this one are paid by scanning them inside your banking or wallet app.")
        }
        Kind.TEXT -> f["embedded_urls"]?.split(' ')?.firstOrNull { it.isNotBlank() }
            ?.let { found -> Proceed.Browse(if (found.startsWith("www.", ignoreCase = true)) "http://$found" else found) }
            ?: Proceed.CopyOnly("It's plain text, so there's nothing to open.")
        Kind.BINARY -> Proceed.CopyOnly("It's raw data, so there's nothing to open.")
    }
}

private fun contactCard(f: Map<String, String>): ContactCard {
    fun many(key: String) = f[key].orEmpty().split(", ").map { it.trim() }.filter { it.isNotEmpty() }
    return ContactCard(
        name = f["name"].orEmpty(),
        phones = many("TEL"),
        emails = many("EMAIL"),
        organisation = f["ORG"].orEmpty().replace(';', ' ').trim(),
        jobTitle = f["TITLE"].orEmpty(),
        // vCard addresses are ";"-separated parts, most of them usually empty.
        address = f["ADR"].orEmpty().split(';', ',').map { it.trim() }.filter { it.isNotEmpty() }.joinToString(", "),
        website = f["URL"].orEmpty(),
        note = f["NOTE"].orEmpty(),
    )
}

private fun calendarEvent(f: Map<String, String>): Proceed {
    val start = f["DTSTART"]?.let(::parseIcalTime)
    val end = f["DTEND"]?.let(::parseIcalTime)
    return Proceed.AddEvent(
        title = f["SUMMARY"].orEmpty(),
        startMillis = start?.first,
        endMillis = end?.first,
        allDay = start?.second ?: false,
        location = f["LOCATION"].orEmpty(),
        description = f["DESCRIPTION"].orEmpty(),
    )
}

/**
 * iCalendar times (RFC 5545): "20261005T150000Z" is UTC, "20261005T150000"
 * is local time and "20261005" is a whole day. Returns epoch millis and
 * whether it's all-day, or null if it can't be read.
 */
fun parseIcalTime(value: String, zone: ZoneId = ZoneId.systemDefault()): Pair<Long, Boolean>? {
    val v = value.trim()
    return try {
        when {
            v.length == 8 -> LocalDate.parse(v, DateTimeFormatter.BASIC_ISO_DATE)
                .atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli() to true
            v.endsWith("Z") -> LocalDateTime.parse(v.dropLast(1), ICAL_TIME)
                .toInstant(ZoneOffset.UTC).toEpochMilli() to false
            else -> LocalDateTime.parse(v, ICAL_TIME).atZone(zone).toInstant().toEpochMilli() to false
        }
    } catch (_: Exception) {
        null
    }
}

private val ICAL_TIME = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss")
