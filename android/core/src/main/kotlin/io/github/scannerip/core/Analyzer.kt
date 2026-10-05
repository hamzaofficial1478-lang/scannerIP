package io.github.scannerip.core

/*
 * Look for red flags in a scanned payload before anything acts on it.
 *
 * These are heuristics, not a guarantee. A clean result means "nothing obvious
 * jumped out", never "this is definitely safe". The rules are based on common
 * QR phishing ("quishing") tricks: links hidden behind shorteners, look-alike
 * domains, bare IP addresses, swapped payment stickers and so on.
 */

enum class Severity(val points: Int) { INFO(0), LOW(10), MEDIUM(25), HIGH(45), CRITICAL(80) }

enum class Level(val floor: Int, val advice: String) {
    DANGEROUS(80, "Do not open this. Delete the photo and move on."),
    HIGH(45, "Very likely a trap. Don't open it unless you can check it some other way."),
    MEDIUM(25, "Be careful. Check where it really goes before you trust it."),
    LOW(10, "Minor warning signs. Probably fine, but have a look first."),
    CLEAN(0, "No red flags found. That's not a promise it's safe, just nothing obvious."),
}

data class Finding(val severity: Severity, val message: String)

class Report(val payload: Payload, val findings: List<Finding>) {
    val score: Int get() = minOf(100, findings.sumOf { it.severity.points })
    val level: Level get() = Level.entries.first { score >= it.floor }
    val advice: String get() = level.advice
}

val SHORTENERS = setOf(
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "qrco.de", "s.id", "v.gd", "shorte.st", "adf.ly", "bl.ink", "lnkd.in",
)

// TLDs that turn up a lot in abuse reports (cheap or free to register) plus the
// newer ones that look like file names.
val RISKY_TLDS = setOf(
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "support", "rest", "cam", "icu", "monster", "buzz", "cyou", "sbs",
)

val DANGEROUS_EXTENSIONS = setOf(
    "apk", "exe", "msi", "bat", "cmd", "scr", "ps1", "vbs", "js", "jar", "dmg",
    "pkg", "deb", "sh", "hta", "lnk", "iso", "img", "docm", "xlsm", "pptm", "reg",
    "mobileconfig", "ipa", "xapk", "apks",
)

val BRANDS = sortedSetOf(
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google",
    "gmail", "amazon", "facebook", "instagram", "whatsapp", "netflix", "binance",
    "coinbase", "metamask", "dhl", "fedex", "ups", "royalmail", "hmrc", "nhs",
    "easypaisa", "jazzcash", "hbl", "meezan", "steam", "roblox", "tiktok",
    "snapchat", "linkedin", "dropbox", "docusign",
)

// Real domains a brand owns that don't simply start with "<brand>.".
val OFFICIAL_DOMAINS = mapOf(
    "microsoft" to setOf("microsoftonline.com", "microsoft365.com", "office.com", "live.com", "azure.com"),
    "google" to setOf("googleapis.com", "googleusercontent.com", "gstatic.com", "googlevideo.com"),
    "amazon" to setOf("amazonaws.com", "amazon-adsystem.com"),
    "paypal" to setOf("paypalobjects.com", "paypal-community.com"),
    "steam" to setOf("steampowered.com", "steamcommunity.com", "steamstatic.com"),
    "apple" to setOf("apple.news", "applecard.apple"),
    "facebook" to setOf("facebookmail.com"),
    "dropbox" to setOf("dropboxusercontent.com"),
)

val PHISHY_WORDS = listOf(
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account",
    "update", "secure", "banking", "password", "wallet", "confirm", "suspend",
    "unlock", "reward", "prize", "free-gift", "claim",
)

// Two-part public suffixes, enough for a rough "registrable domain" guess.
val SECOND_LEVEL_SUFFIXES = setOf(
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "nhs.uk", "me.uk",
    "com.pk", "org.pk", "edu.pk", "gov.pk", "net.pk", "com.au", "net.au",
    "org.au", "co.in", "co.jp", "com.br", "co.nz", "co.za", "com.cn", "com.tr",
    "com.sa", "com.my", "com.sg", "co.ke", "com.ng", "com.eg",
)

// Home/office networks, loopback and link-local: where routers and printers live.
private val LOCAL_NETWORKS: List<Pair<ByteArray, Int>> = listOf(
    "10.0.0.0" to 8, "172.16.0.0" to 12, "192.168.0.0" to 16, "127.0.0.0" to 8,
    "169.254.0.0" to 16, "::1" to 128, "fc00::" to 7, "fe80::" to 10,
).map { (net, prefix) -> IpLiteral.parse(net)!! to prefix }

private val SCRIPT_RE = Regex(
    "<script|javascript:|powershell|cmd\\.exe|/bin/(ba)?sh|curl\\s+\\S+\\s*\\|\\s*(ba)?sh" +
        "|wget\\s+http|rm\\s+-rf|eval\\(|invoke-expression|certutil\\s+-urlcache",
    RegexOption.IGNORE_CASE,
)
val BIDI_CHARS = setOf('‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩')
val ZERO_WIDTH = setOf('​', '‌', '‍', '⁠', '﻿')

fun analyse(payload: Payload): Report {
    val found = mutableListOf<Finding>()
    if (!payload.isBinary) checkHiddenCharacters(payload.raw, found)
    when (payload.kind) {
        Kind.URL -> {
            if (!payload.fields["note"].isNullOrEmpty()) {
                found += Finding(Severity.LOW, "No http/https given, so a phone would open it as plain http.")
            }
            checkUrl(payload.fields.getValue("url"), found)
        }
        Kind.WIFI -> checkWifi(payload, found)
        Kind.SMS -> checkSms(payload, found)
        Kind.PHONE -> checkPhone(payload, found)
        Kind.EMAIL -> checkTextLinks(payload.fields["body"] ?: "", found)
        Kind.CONTACT, Kind.CALENDAR -> payload.fields.values.forEach { checkTextLinks(it, found) }
        Kind.OTP -> found += Finding(Severity.LOW, "Adds an account to your authenticator app. Only scan this " +
            "if you're setting up 2FA on that site right now, and never share a photo of it.")
        Kind.CRYPTO -> found += Finding(Severity.MEDIUM, "Crypto payment request. Scammers swap these codes so " +
            "money goes to them - check the address character by character. Crypto can't be refunded.")
        Kind.PAYMENT -> {
            found += Finding(Severity.MEDIUM, "Payment code. Fake stickers over real ones (parking meters, " +
                "shop counters) are a known scam - check the merchant name before paying.")
            if (payload.fields["crc_ok"] == "no") {
                found += Finding(Severity.HIGH, "The payment code's checksum doesn't match. It's been edited or damaged.")
            }
        }
        Kind.TEXT -> {
            if (SCRIPT_RE.containsMatchIn(payload.raw)) {
                found += Finding(Severity.HIGH, "Contains what looks like commands or script code. " +
                    "Never paste this into a terminal or browser.")
            }
            checkTextLinks(payload.raw, found)
        }
        Kind.BINARY -> found += Finding(Severity.MEDIUM, "Raw binary data rather than text. Normal QR codes " +
            "rarely need this, so don't feed it to other apps.")
        Kind.GEO -> {}
    }
    // The same link can show up in several fields, so drop repeats.
    return Report(payload, found.distinct())
}

fun analyseText(text: String): Report = analyse(classify(text))

/** Swap invisible/direction-changing characters for a visible tag like <U+202E>. */
fun makeVisible(text: String): String = buildString {
    for (ch in text) {
        if (ch in BIDI_CHARS || ch in ZERO_WIDTH || (ch.code < 32 && ch !in "\r\n\t")) {
            append("<U+%04X>".format(ch.code))
        } else {
            append(ch)
        }
    }
}

/** Best-effort 'example.co.uk' from 'login.example.co.uk' (no full PSL). */
fun registrableDomain(host: String): String {
    val labels = host.lowercase().trimEnd('.').split('.')
    if (labels.size >= 3 && labels.takeLast(2).joinToString(".") in SECOND_LEVEL_SUFFIXES) {
        return labels.takeLast(3).joinToString(".")
    }
    return labels.takeLast(2).joinToString(".")
}

/** Run all the link checks, appending findings to `out`. */
fun checkUrl(url: String, out: MutableList<Finding>, nested: Boolean = false) {
    val prefix = if (nested) "Embedded link: " else ""
    fun add(severity: Severity, message: String) { out += Finding(severity, prefix + message) }
    val parts = UrlParts.split(url)
    val scheme = parts.scheme

    when (scheme) {
        "javascript", "vbscript" -> return add(Severity.CRITICAL, "Runs script code the moment it's opened.")
        "data" -> return add(Severity.HIGH, "A 'data:' link carries a whole page or file inside " +
            "the code. Classic way to fake a login page.")
        "file" -> return add(Severity.HIGH, "Points at a file on your own device.")
        "intent" -> return add(Severity.HIGH, "Android intent link: can launch apps directly.")
        "itms-services" -> return add(Severity.CRITICAL, "Tries to install an iOS app from outside the App Store.")
        "http" -> add(Severity.MEDIUM, "Not encrypted (http). Anyone on the same network " +
            "can read or change what comes back.")
        "https" -> {}
        "ftp" -> add(Severity.LOW, "Old-fashioned FTP link, unencrypted.")
        else -> return add(Severity.MEDIUM, "Opens another app ('$scheme:') rather than a web page.")
    }

    val host: String
    val port: Int?
    try {
        host = parts.hostname ?: ""
        port = parts.port
    } catch (e: IllegalArgumentException) {
        return add(Severity.HIGH, "The link is malformed (bad host or port).")
    }
    if (host.isEmpty()) return add(Severity.HIGH, "Link has no proper host name.")

    if ('@' in parts.netloc) {
        add(Severity.HIGH, "Contains '@'. Everything before it is ignored, so the real site is '$host'.")
    }

    val ip = asIp(host)
    if (ip != null) {
        add(Severity.HIGH, "Uses a bare IP address instead of a name. Real companies almost never do this.")
        if (LOCAL_NETWORKS.any { (net, prefix) -> IpLiteral.inNetwork(ip, net, prefix) }) {
            add(Severity.MEDIUM, "Points into a local/private network (router pages, internal devices).")
        }
    } else {
        checkHostname(host, out, prefix)
    }

    if (port != null && port != 80 && port != 443) add(Severity.LOW, "Uses an unusual port ($port).")

    val path = percentDecode(parts.path).lowercase()
    val lastSegment = path.substringAfterLast('/')
    val ext = if ('.' in lastSegment) path.substringAfterLast('.') else ""
    if (ext in DANGEROUS_EXTENSIONS) {
        add(Severity.CRITICAL, "Downloads a '.$ext' file. That's an app or script that could install malware.")
    }

    val rest = (path + "?" + percentDecode(parts.query)).lowercase()
    if (ip == null) {
        val domain = registrableDomain(host)
        val brand = impersonatedBrand(path, domain)
        if (brand != null && impersonatedBrand(host, domain) == null) {
            add(Severity.LOW, "Talks about '$brand' in the link, but the site is '$domain'.")
        }
    }
    val words = PHISHY_WORDS.filter { it in rest }.toSortedSet()
    if (words.isNotEmpty()) add(Severity.LOW, "Uses words phishing pages love: " + words.take(4).joinToString(", "))

    for ((key, values) in parseQuery(parts.query)) {
        if (values.any { v -> v.lowercase().let { it.startsWith("http://") || it.startsWith("https://") || it.startsWith("//") } }) {
            add(Severity.MEDIUM, "Passes another link in '$key=' - a common way to bounce you somewhere else.")
            break
        }
    }

    if (url.length > 200) add(Severity.LOW, "Very long link (${url.length} characters), often used to hide the real part.")
    if (url.count { it == '%' } > 10) add(Severity.LOW, "Heavily percent-encoded, which can hide what it says.")
}

private fun checkHostname(host: String, out: MutableList<Finding>, prefix: String) {
    fun add(severity: Severity, message: String) { out += Finding(severity, prefix + message) }
    if (!host.all { it.code < 128 }) {
        add(Severity.HIGH, "Domain uses non-English letters that can imitate a real site (homograph attack).")
    }
    if ("xn--" in host) {
        val shown = try { java.net.IDN.toUnicode(host, java.net.IDN.ALLOW_UNASSIGNED) } catch (e: IllegalArgumentException) { host }
        add(Severity.HIGH, "Punycode domain - it really displays as '$shown', which may imitate a real site.")
    }

    val domain = registrableDomain(host)
    if (domain in SHORTENERS || host in SHORTENERS) {
        add(Severity.MEDIUM, "Link shortener ($domain) hides the real destination.")
    }

    val tld = host.substringAfterLast('.')
    if (tld in RISKY_TLDS) add(Severity.LOW, "Ends in '.$tld', a domain ending abused a lot by scammers.")

    if (host.count { it == '.' } >= 4) add(Severity.LOW, "Lots of subdomains stacked up, often used to look official.")

    impersonatedBrand(host, domain)?.let { brand ->
        add(Severity.HIGH, "Mentions '$brand' but the real domain is '$domain'. Looks like impersonation.")
    }
}

// Short names need a boundary both sides, or "ups" would match "upset".
private val BRAND_PATTERNS = BRANDS.associateWith { brand ->
    Regex("(?<![a-z0-9])$brand" + if (brand.length <= 4) "(?![a-z0-9])" else "")
}

/** Return a brand named in `text` that `domain` doesn't actually belong to. */
fun impersonatedBrand(text: String, domain: String): String? {
    val labels = domain.split('.')
    for ((brand, pattern) in BRAND_PATTERNS) {
        // "paypal.co.uk" or "trust.nhs.uk" really do belong to the brand.
        if (brand in labels || domain in OFFICIAL_DOMAINS[brand].orEmpty()) continue
        if (pattern.containsMatchIn(text)) return brand
    }
    return null
}

/** An IP literal (or the plain-number forms browsers accept), never via DNS. */
fun asIp(host: String): ByteArray? {
    IpLiteral.parse(host.removePrefix("[").removeSuffix("]"))?.let { return it }
    // Browsers also accept a plain decimal or hex number as an IPv4 address.
    if (Regex("\\d{8,10}|0x[0-9a-f]{8}").matches(host)) {
        val value = if (host.startsWith("0x")) host.substring(2).toLong(16) else host.toLong()
        if (value in 0..0xFFFFFFFFL) {
            return ByteArray(4) { i -> ((value shr (24 - 8 * i)) and 0xff).toByte() }
        }
    }
    return null
}

private fun checkHiddenCharacters(text: String, out: MutableList<Finding>) {
    if (text.any { it in BIDI_CHARS }) {
        out += Finding(Severity.HIGH, "Hidden text-direction characters that make the content " +
            "display differently from what it really says.")
    }
    if (text.any { it in ZERO_WIDTH }) out += Finding(Severity.MEDIUM, "Contains invisible zero-width characters.")
    if (text.any { it.code < 32 && it !in "\r\n\t" }) {
        out += Finding(Severity.MEDIUM, "Contains invisible control characters.")
    }
}

private fun checkWifi(p: Payload, out: MutableList<Finding>) {
    when ((p.fields["T"] ?: "").uppercase()) {
        "", "NOPASS", "NONE" -> out += Finding(Severity.MEDIUM, "Open network with no password. " +
            "Whoever runs it can watch your unencrypted traffic.")
        "WEP" -> out += Finding(Severity.MEDIUM, "Uses WEP, which has been broken for years.")
    }
    if ((p.fields["H"] ?: "").lowercase() == "true") {
        out += Finding(Severity.LOW, "Hidden network. Unusual for a public Wi-Fi code.")
    }
    out += Finding(Severity.INFO, "Joining a network hands its owner a view of your traffic. " +
        "Only join if you trust who put the code there.")
}

private fun checkSms(p: Payload, out: MutableList<Finding>) {
    val digits = (p.fields["number"] ?: "").filter { it.isDigit() }
    if (digits.length in 1..6) {
        out += Finding(Severity.HIGH, "Sends to a short code ($digits). Premium-rate SMS scams use these to charge your bill.")
    }
    if (!p.fields["body"].isNullOrEmpty()) {
        out += Finding(Severity.INFO, "Message is pre-written. Read it before you hit send.")
    }
    checkTextLinks(p.fields["body"] ?: "", out)
}

private fun checkPhone(p: Payload, out: MutableList<Finding>) {
    val number = p.fields["number"] ?: ""
    if ('*' in number || '#' in number) {
        out += Finding(Severity.CRITICAL, "This is a USSD/MMI code, not a phone number. These can " +
            "change phone settings, divert calls or show your IMEI.")
        return
    }
    val digits = number.filter { it.isDigit() }
    if (digits.length in 1..6) out += Finding(Severity.MEDIUM, "Very short number - could be a premium-rate service.")
    if ((digits.startsWith("449") || digits.startsWith("09")) && digits.length > 6) {
        out += Finding(Severity.MEDIUM, "Looks like a premium-rate number (09...).")
    }
}

private fun checkTextLinks(text: String, out: MutableList<Finding>) {
    for (match in EMBEDDED_URL_RE.findAll(text).take(5)) {
        val link = match.value
        checkUrl(if ("://" in link) link else "http://$link", out, nested = true)
    }
}
