package io.github.scannerip.core

import java.io.ByteArrayOutputStream

/**
 * Splits a link into its parts without judging it, the same way Python's
 * urllib.parse.urlsplit does (the desktop version relied on that). It has to
 * cope with any scheme - javascript:, data:, intent: - and with deliberately
 * odd links, so java.net.URI is far too strict for the job.
 */
class UrlParts private constructor(
    val scheme: String,
    val netloc: String,
    val path: String,
    val query: String,
    val fragment: String,
) {
    /** Host with user info, port and IPv6 brackets removed, lower-cased. */
    val hostname: String?
        get() {
            val hostPort = netloc.substringAfterLast('@')
            if (hostPort.startsWith("[")) {
                val end = hostPort.indexOf(']')
                return if (end > 1) hostPort.substring(1, end).lowercase() else null
            }
            return hostPort.substringBefore(':').lowercase().ifEmpty { null }
        }

    /** Port number, or null if none was given. Throws on rubbish, like Python. */
    val port: Int?
        get() {
            val hostPort = netloc.substringAfterLast('@')
            val afterHost = if (hostPort.startsWith("[")) hostPort.substringAfter(']', "") else {
                if (':' in hostPort) ":" + hostPort.substringAfter(':') else ""
            }
            if (!afterHost.startsWith(":")) return null
            val text = afterHost.substring(1)
            if (text.isEmpty()) return null
            require(text.all { it in '0'..'9' }) { "Port could not be cast to integer value" }
            val value = text.toBigInteger()
            require(value <= 65535.toBigInteger()) { "Port out of range 0-65535" }
            return value.toInt()
        }

    companion object {
        private val SCHEME_CHARS = ('a'..'z') + ('A'..'Z') + ('0'..'9') + listOf('+', '-', '.')

        fun split(url: String): UrlParts {
            // Python strips surrounding whitespace and drops tabs and newlines.
            var rest = url.trim().filterNot { it == '\t' || it == '\r' || it == '\n' }
            var scheme = ""
            val colon = rest.indexOf(':')
            if (colon > 0 && rest[0].isAsciiLetter() && rest.substring(0, colon).all { it in SCHEME_CHARS }) {
                scheme = rest.substring(0, colon).lowercase()
                rest = rest.substring(colon + 1)
            }
            var netloc = ""
            if (rest.startsWith("//")) {
                val end = rest.indexOfAny(charArrayOf('/', '?', '#'), 2).let { if (it < 0) rest.length else it }
                netloc = rest.substring(2, end)
                rest = rest.substring(end)
            }
            var fragment = ""
            rest.indexOf('#').takeIf { it >= 0 }?.let { fragment = rest.substring(it + 1); rest = rest.substring(0, it) }
            var query = ""
            rest.indexOf('?').takeIf { it >= 0 }?.let { query = rest.substring(it + 1); rest = rest.substring(0, it) }
            return UrlParts(scheme, netloc, rest, query, fragment)
        }

        private fun Char.isAsciiLetter() = this in 'a'..'z' || this in 'A'..'Z'
    }
}

/** Python's urllib.parse.unquote: decode %XX as UTF-8, leave anything malformed alone. */
fun percentDecode(text: String): String {
    if ('%' !in text) return text
    val out = StringBuilder()
    val bytes = ByteArrayOutputStream()
    fun flush() {
        if (bytes.size() > 0) {
            out.append(bytes.toByteArray().toString(Charsets.UTF_8))
            bytes.reset()
        }
    }
    var i = 0
    while (i < text.length) {
        val c = text[i]
        if (c == '%' && i + 2 < text.length && isHex(text[i + 1]) && isHex(text[i + 2])) {
            bytes.write(text.substring(i + 1, i + 3).toInt(16))
            i += 3
        } else {
            flush()
            out.append(c)
            i++
        }
    }
    flush()
    return out.toString()
}

private fun isHex(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

/** Python's parse_qs: '+' means space, pairs without '=' or with a blank value are skipped. */
fun parseQuery(query: String): Map<String, List<String>> {
    val result = LinkedHashMap<String, MutableList<String>>()
    for (pair in query.split('&')) {
        if (pair.isEmpty() || '=' !in pair) continue
        val name = percentDecode(pair.substringBefore('=').replace('+', ' '))
        val value = percentDecode(pair.substringAfter('=').replace('+', ' '))
        if (value.isEmpty()) continue
        result.getOrPut(name) { mutableListOf() }.add(value)
    }
    return result
}

/** Strict IP literal parsing that never touches DNS. */
object IpLiteral {
    /** "203.0.113.7" -> 4 bytes. No leading zeros, every part 0-255. */
    fun parseV4(text: String): ByteArray? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for ((i, part) in parts.withIndex()) {
            if (part.isEmpty() || part.length > 3 || !part.all { it in '0'..'9' }) return null
            if (part.length > 1 && part[0] == '0') return null
            val n = part.toInt()
            if (n > 255) return null
            out[i] = n.toByte()
        }
        return out
    }

    /** IPv6 literal -> 16 bytes, or null. Handles "::" and an embedded IPv4 tail. */
    fun parseV6(text: String): ByteArray? {
        val body = text.substringBefore('%') // drop any zone id
        if (':' !in body || !body.all { it == ':' || it == '.' || isHex(it) }) return null
        val halves = body.split("::")
        if (halves.size > 2) return null
        val all: List<Int> = if (halves.size == 2) {
            val head = words(halves[0], v4AtEnd = false) ?: return null
            val tail = words(halves[1], v4AtEnd = true) ?: return null
            val missing = 8 - head.size - tail.size
            if (missing < 1) return null
            head + List(missing) { 0 } + tail
        } else {
            words(body, v4AtEnd = true)?.takeIf { it.size == 8 } ?: return null
        }
        return ByteArray(16) { i -> ((all[i / 2] shr (if (i % 2 == 0) 8 else 0)) and 0xff).toByte() }
    }

    private fun words(part: String, v4AtEnd: Boolean): List<Int>? {
        if (part.isEmpty()) return emptyList()
        val groups = part.split(':')
        val out = mutableListOf<Int>()
        for ((i, g) in groups.withIndex()) {
            when {
                g.isEmpty() || g.length > 4 && '.' !in g -> return null
                '.' in g -> {
                    if (!v4AtEnd || i != groups.lastIndex) return null
                    val v4 = parseV4(g) ?: return null
                    out += ((v4[0].toInt() and 0xff) shl 8) or (v4[1].toInt() and 0xff)
                    out += ((v4[2].toInt() and 0xff) shl 8) or (v4[3].toInt() and 0xff)
                }
                else -> out += g.toInt(16)
            }
        }
        return out
    }

    fun parse(text: String): ByteArray? = parseV4(text) ?: parseV6(text.removePrefix("[").removeSuffix("]"))

    fun format(bytes: ByteArray): String =
        if (bytes.size == 4) bytes.joinToString(".") { (it.toInt() and 0xff).toString() }
        else java.net.InetAddress.getByAddress(bytes).hostAddress

    /** Is `ip` inside network/prefix? Both must be the same family. */
    fun inNetwork(ip: ByteArray, network: ByteArray, prefix: Int): Boolean {
        if (ip.size != network.size) return false
        var bits = prefix
        for (i in ip.indices) {
            if (bits <= 0) return true
            val mask = if (bits >= 8) 0xff else (0xff shl (8 - bits)) and 0xff
            if ((ip[i].toInt() and mask) != (network[i].toInt() and mask)) return false
            bits -= 8
        }
        return true
    }
}
