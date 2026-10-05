package io.github.scannerip.core

/*
 * Work out what kind of data a scanned code is carrying.
 *
 * A QR code is only ever text (or raw bytes). It can't run anything by itself.
 * The danger comes from what a phone *does* with that text: opening a link,
 * joining a Wi-Fi network, dialling a number, paying someone. So the first job
 * is to label the payload properly, before anything is allowed to act on it.
 *
 * Formats follow the de facto conventions documented on the ZXing wiki
 * ("Barcode Contents"), EMVCo for merchant payment codes, and the usual URI
 * schemes (RFC 3986, RFC 6068 mailto, RFC 3966 tel, RFC 5870 geo).
 */

enum class Kind(val label: String) {
    URL("Web link / app link"),
    WIFI("Wi-Fi network"),
    CONTACT("Contact card"),
    EMAIL("Email"),
    SMS("Text message"),
    PHONE("Phone number"),
    GEO("Map location"),
    CALENDAR("Calendar event"),
    OTP("2FA / authenticator setup"),
    CRYPTO("Crypto payment"),
    PAYMENT("Merchant payment"),
    TEXT("Plain text"),
    BINARY("Binary data"),
}

class Payload(
    val kind: Kind,
    val raw: String,
    val fields: Map<String, String> = emptyMap(),
    val isBinary: Boolean = false,
) {
    val label: String get() = kind.label

    /** One line a human can read without the payload doing anything. */
    fun summary(): String {
        val f = fields
        return when (kind) {
            Kind.URL -> f["url"] ?: raw
            Kind.WIFI -> "Network '${f["S"] ?: "?"}' (security: ${f["T"]?.ifEmpty { null } ?: "none"})"
            Kind.CONTACT -> f["name"]?.ifEmpty { null } ?: f["FN"]?.ifEmpty { null } ?: "Unnamed contact"
            Kind.EMAIL -> "To ${f["to"] ?: "?"} - subject: ${f["subject"] ?: ""}"
            Kind.SMS -> "To ${f["number"] ?: "?"}: ${f["body"] ?: ""}"
            Kind.PHONE -> f["number"] ?: raw
            Kind.GEO -> "${f["lat"]}, ${f["lon"]}"
            Kind.CALENDAR -> f["SUMMARY"] ?: "Untitled event"
            Kind.OTP -> "${f["issuer"] ?: "?"} - ${f["account"] ?: "?"} (secret hidden)"
            Kind.CRYPTO -> "${f["coin"]} to ${f["address"]} ${f["amount"] ?: ""}".trim()
            Kind.PAYMENT -> "Pay ${f["merchant"] ?: "?"} ${f["amount"] ?: ""}".trim()
            Kind.BINARY -> "${raw.length / 2} bytes of binary data"
            Kind.TEXT -> raw.replace("\n", " ").let { if (it.length <= 80) it else it.take(77) + "..." }
        }
    }
}

// Schemes that don't use "//" but are still links a phone will happily act on.
val OPAQUE_SCHEMES = setOf(
    "javascript", "vbscript", "data", "file", "intent", "market",
    "itms-apps", "itms-services", "about", "blob", "content",
)

val CRYPTO_SCHEMES = setOf(
    "bitcoin", "bitcoincash", "litecoin", "ethereum", "dogecoin",
    "monero", "solana", "tron", "ripple", "cardano",
)

private val SCHEME_RE = Regex("^([a-zA-Z][a-zA-Z0-9+.\\-]{0,30}):(.*)$", RegexOption.DOT_MATCHES_ALL)
val EMBEDDED_URL_RE = Regex("(?:https?://|www\\.)[^\\s<>\"']+", RegexOption.IGNORE_CASE)
private val WWW_RE = Regex("^www\\.\\S+\\.[a-z]{2,}", RegexOption.IGNORE_CASE)

/** Turn decoded text into a labelled Payload. */
fun classify(text: String, rawBytes: ByteArray? = null, isBinary: Boolean = false): Payload {
    if (isBinary) {
        val data = rawBytes ?: text.toByteArray(Charsets.ISO_8859_1)
        return Payload(Kind.BINARY, data.toHex(), mapOf("length" to data.size.toString()), isBinary = true)
    }

    val stripped = text.trim()
    val upper = stripped.uppercase()

    when {
        upper.startsWith("WIFI:") -> return Payload(Kind.WIFI, text, splitFields(stripped.substring(5)))
        upper.startsWith("MECARD:") -> {
            val f = splitFields(stripped.substring(7)).toMutableMap()
            var name = f["N"] ?: ""
            if (',' in name) { // MECARD writes "Surname,Firstname"
                name = "${name.substringAfter(',')} ${name.substringBefore(',')}".trim()
            }
            f["name"] = name
            return Payload(Kind.CONTACT, text, f)
        }
        upper.startsWith("BEGIN:VCARD") -> {
            val f = parseIcalLike(stripped).toMutableMap()
            f["name"] = f["FN"]?.ifEmpty { null } ?: (f["N"] ?: "").replace(";", " ").trim()
            return Payload(Kind.CONTACT, text, f)
        }
        upper.startsWith("BEGIN:VEVENT") || upper.startsWith("BEGIN:VCALENDAR") ->
            return Payload(Kind.CALENDAR, text, parseIcalLike(stripped))
        upper.startsWith("MATMSG:") -> {
            val f = splitFields(stripped.substring(7))
            return Payload(Kind.EMAIL, text, mapOf(
                "to" to (f["TO"] ?: ""), "subject" to (f["SUB"] ?: ""), "body" to (f["BODY"] ?: "")))
        }
        upper.startsWith("SMSTO:") || upper.startsWith("SMS:") -> return Payload(Kind.SMS, text, parseSms(stripped))
        upper.startsWith("MAILTO:") -> return Payload(Kind.EMAIL, text, parseMailto(stripped))
        upper.startsWith("TEL:") ->
            return Payload(Kind.PHONE, text, mapOf("number" to percentDecode(stripped.substring(4)).trim()))
        upper.startsWith("GEO:") -> return Payload(Kind.GEO, text, parseGeo(stripped))
        upper.startsWith("OTPAUTH://") -> return Payload(Kind.OTP, text, parseOtpauth(stripped))
        upper.startsWith("UPI://") -> {
            val q = parseQuery(UrlParts.split(stripped).query).mapValues { it.value.first() }
            return Payload(Kind.PAYMENT, text, mapOf(
                "scheme" to "UPI", "merchant" to (q["pn"] ?: q["pa"] ?: ""),
                "account" to (q["pa"] ?: ""), "amount" to (q["am"] ?: "")))
        }
        stripped.startsWith("000201") -> parseEmvco(stripped)?.let { return Payload(Kind.PAYMENT, text, it) }
    }

    SCHEME_RE.find(stripped)?.let { m ->
        val scheme = m.groupValues[1].lowercase()
        val rest = m.groupValues[2]
        if (scheme in CRYPTO_SCHEMES) return Payload(Kind.CRYPTO, text, parseCrypto(scheme, rest))
        if (rest.startsWith("//") || scheme in OPAQUE_SCHEMES) {
            return Payload(Kind.URL, text, mapOf("url" to stripped, "scheme" to scheme))
        }
    }

    if (WWW_RE.containsMatchIn(stripped) && ' ' !in stripped) {
        // Most phones open "www.something.com" as a link, so treat it as one.
        return Payload(Kind.URL, text, mapOf(
            "url" to "http://$stripped", "scheme" to "http",
            "note" to "no scheme - a phone would assume http"))
    }

    return Payload(Kind.TEXT, text, mapOf(
        "embedded_urls" to EMBEDDED_URL_RE.findAll(text).joinToString(" ") { it.value }))
}

/** Parse ZXing/MECARD style 'K:value;K2:value;;' with backslash escapes. */
internal fun splitFields(body: String): Map<String, String> {
    val fields = LinkedHashMap<String, String>()
    var key = ""
    val buf = StringBuilder()
    var inValue = false
    var escaped = false
    fun store() {
        if (inValue && key.isNotEmpty()) {
            val value = buf.toString()
            fields[key] = fields[key]?.let { "$it, $value" } ?: value
        }
    }
    for (ch in body) {
        when {
            escaped -> { buf.append(ch); escaped = false }
            ch == '\\' -> escaped = true
            ch == ':' && !inValue -> { key = buf.toString().trim().uppercase(); buf.clear(); inValue = true }
            ch == ';' -> { store(); key = ""; buf.clear(); inValue = false }
            else -> buf.append(ch)
        }
    }
    store()
    return fields
}

/** Rough reader for vCard / iCalendar: KEY;params:value lines. */
internal fun parseIcalLike(text: String): Map<String, String> {
    val unfolded = text.replace(Regex("\\r?\\n[ \\t]"), "") // RFC 6350 line folding
    val fields = LinkedHashMap<String, String>()
    for (line in unfolded.lines()) {
        if (':' !in line) continue
        val key = line.substringBefore(':').substringBefore(';').trim().uppercase()
        if (key in setOf("BEGIN", "END", "VERSION")) continue
        val value = line.substringAfter(':').trim()
        fields[key] = fields[key]?.let { "$it, $value" } ?: value
    }
    return fields
}

private fun parseSms(text: String): Map<String, String> {
    if (text.uppercase().startsWith("SMSTO:")) {
        val rest = text.substring(6)
        return mapOf("number" to rest.substringBefore(':').trim(), "body" to rest.substringAfter(':', ""))
    }
    val rest = text.substring(4)
    val sep = rest.indexOfFirst { it == '?' || it == ';' || it == '&' }
    val number = if (sep >= 0) rest.substring(0, sep) else rest
    val query = if (sep >= 0) rest.substring(sep + 1) else ""
    return mapOf("number" to percentDecode(number).trim(), "body" to (parseQuery(query)["body"]?.first() ?: ""))
}

private fun parseMailto(text: String): Map<String, String> {
    val parts = UrlParts.split(text)
    val q = parseQuery(parts.query).mapKeys { it.key.lowercase() }.mapValues { it.value.first() }
    return mapOf("to" to percentDecode(parts.path), "subject" to (q["subject"] ?: ""), "body" to (q["body"] ?: ""))
}

private fun parseGeo(text: String): Map<String, String> {
    val body = text.substring(4)
    val coords = body.substringBefore('?')
    val bits = coords.split(',')
    val out = linkedMapOf("lat" to bits[0].trim(), "lon" to (bits.getOrNull(1)?.trim() ?: ""))
    if ('?' in body) out["query"] = percentDecode(body.substringAfter('?'))
    return out
}

private fun parseOtpauth(text: String): Map<String, String> {
    val parts = UrlParts.split(text)
    val q = parseQuery(parts.query).mapKeys { it.key.lowercase() }.mapValues { it.value.first() }
    val label = percentDecode(parts.path.trimStart('/'))
    val issuer = if (':' in label) label.substringBefore(':') else ""
    val account = if (':' in label) label.substringAfter(':') else label
    val secret = q["secret"] ?: ""
    return mapOf(
        "type" to parts.netloc.lowercase(),
        "issuer" to (q["issuer"] ?: issuer),
        "account" to account,
        // Never show the full secret: anyone holding it can generate your codes.
        "secret" to if (secret.isEmpty()) "" else secret.take(2) + "*".repeat(maxOf(secret.length - 2, 0)),
    )
}

private fun parseCrypto(scheme: String, rest: String): Map<String, String> {
    val body = rest.trimStart('/')
    val q = parseQuery(body.substringAfter('?', "")).mapKeys { it.key.lowercase() }.mapValues { it.value.first() }
    val out = linkedMapOf("coin" to scheme, "address" to body.substringBefore('?'))
    q["amount"]?.let { out["amount"] = it }
    q["label"]?.let { out["label"] = it }
    return out
}

/** CRC-16/CCITT-FALSE as used by EMVCo merchant QR codes (tag 63). */
fun emvCrc16(data: String): String {
    var crc = 0xFFFF
    for (byte in data.toByteArray(Charsets.UTF_8)) {
        crc = crc xor ((byte.toInt() and 0xff) shl 8)
        repeat(8) {
            crc = if (crc and 0x8000 != 0) (crc shl 1) xor 0x1021 else crc shl 1
            crc = crc and 0xFFFF
        }
    }
    return "%04X".format(crc)
}

/** Read the top-level TLV fields of an EMVCo merchant-presented QR. */
private fun parseEmvco(text: String): Map<String, String>? {
    val tags = LinkedHashMap<String, String>()
    var i = 0
    while (i + 4 <= text.length) {
        val tag = text.substring(i, i + 2)
        val length = text.substring(i + 2, i + 4)
        if (!tag.all { it in '0'..'9' } || !length.all { it in '0'..'9' }) return null
        val end = minOf(i + 4 + length.toInt(), text.length)
        tags[tag] = text.substring(i + 4, end)
        i += 4 + length.toInt()
    }
    if (i != text.length || "63" !in tags) return null
    val expected = emvCrc16(text.dropLast(4))
    return mapOf(
        "scheme" to "EMVCo",
        "merchant" to (tags["59"] ?: ""),
        "city" to (tags["60"] ?: ""),
        "amount" to (tags["54"] ?: ""),
        "currency" to (tags["53"] ?: ""),
        "country" to (tags["58"] ?: ""),
        "crc_ok" to if (tags["63"]!!.uppercase() == expected) "yes" else "no",
    )
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
