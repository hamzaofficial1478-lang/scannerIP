package io.github.scannerip.core

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException

/*
 * Check where a link really goes, without opening it in a browser.
 *
 * Shorteners and redirect chains are how most malicious QR links hide. This
 * follows the chain hop by hop through the shield (Tor or a proxy), so the
 * server only ever sees the rotated IP. It sends HEAD requests, never runs any
 * JavaScript, keeps no cookies and never downloads the page body.
 *
 * What it can't see: redirects done with JavaScript or <meta refresh> inside
 * the page, because it deliberately never reads the page.
 */

// A plain, very common browser string. Same for everyone, so it reveals nothing
// about this phone, and cloaking sites behave as they would for a real victim.
val GENERIC_HEADERS = mapOf(
    "User-Agent" to "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept" to "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language" to "en-GB,en;q=0.5",
    "DNT" to "1",
)

val DANGEROUS_TYPES = setOf(
    "application/vnd.android.package-archive",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-ms-installer",
    "application/x-msi",
    "application/java-archive",
    "application/x-sh",
    "application/x-apple-diskimage",
    "application/x-apple-aspen-config",
    "application/hta",
)

data class Hop(
    val url: String,
    val status: Int,
    val contentType: String = "",
    val location: String = "",
    val disposition: String = "",
)

class Inspection(
    val startUrl: String,
    val hops: List<Hop>,
    val report: Report?,
    val extra: List<Finding>,
    val error: String,
) {
    val finalUrl: String get() = hops.lastOrNull()?.url ?: startUrl
}

/** Follow redirects through [route] and analyse where we end up. */
fun inspectUrl(
    url: String,
    route: Route?,
    maxHops: Int = 8,
    timeoutSeconds: Long = 20,
    clientFactory: (Route) -> OkHttpClient = { Net.client(it, timeoutSeconds) },
): Inspection {
    requireNotNull(route) { "Refusing to inspect a link without the shield - that would show the site your real IP address." }
    require(UrlParts.split(url).scheme in setOf("http", "https")) { "Only http/https links can be inspected." }

    val client = clientFactory(route)
    val hops = mutableListOf<Hop>()
    val extra = mutableListOf<Finding>()
    var error = ""
    var current = url
    var finished = false

    for (i in 0 until maxHops) {
        val hop: Hop
        try {
            hop = fetch(client, current, "HEAD").let { first ->
                if (first.status in setOf(403, 405, 501)) fetch(client, current, "GET") else first // some servers refuse HEAD
            }
        } catch (e: IOException) {
            error = "${e.javaClass.simpleName}: ${e.message}"
            finished = true
            break
        } catch (e: IllegalArgumentException) {
            error = "Not a valid web address: ${e.message}"
            finished = true
            break
        }
        hops += hop
        if (hop.status in setOf(301, 302, 303, 307, 308) && hop.location.isNotEmpty()) {
            val target = UrlParts.split(hop.location).scheme
            if (target.isNotEmpty() && target !in setOf("http", "https")) {
                extra += Finding(Severity.HIGH, "Redirects to a non-web link: ${hop.location.take(80)}")
                finished = true
                break
            }
            val next = current.toHttpUrlOrNull()?.resolve(hop.location)
            if (next == null) {
                error = "Redirect to an address that makes no sense: ${hop.location.take(80)}"
                finished = true
                break
            }
            current = next.toString()
            continue
        }
        finished = true
        break
    }
    if (!finished) {
        extra += Finding(Severity.MEDIUM, "More than $maxHops redirects. Legit sites rarely bounce you around this much.")
    }

    if (hops.size > 1) {
        val hosts = hops.map { UrlParts.split(it.url).hostname }.toSet()
        extra += Finding(Severity.INFO, "Went through ${hops.size - 1} redirect(s) across ${hosts.size} different site(s).")
        if (UrlParts.split(hops.last().url).hostname != UrlParts.split(url).hostname) {
            extra += Finding(Severity.LOW, "Ends up on a different site from the one in the code.")
        }
    }
    hops.lastOrNull()?.let { checkDownload(it, extra) }
    val finalUrl = hops.lastOrNull()?.url ?: url
    return Inspection(url, hops, analyseText(finalUrl), extra, error)
}

private fun fetch(client: OkHttpClient, url: String, method: String): Hop {
    val request = Request.Builder().url(url).method(method, null).apply {
        GENERIC_HEADERS.forEach { (k, v) -> header(k, v) }
    }.build()
    // We never read the body: closing straight away drops the connection.
    return client.newCall(request).execute().use { response: Response ->
        Hop(
            url = url,
            status = response.code,
            contentType = response.header("Content-Type").orEmpty(),
            location = response.header("Location").orEmpty(),
            disposition = response.header("Content-Disposition").orEmpty(),
        )
    }
}

private fun checkDownload(hop: Hop, out: MutableList<Finding>) {
    val type = hop.contentType.substringBefore(';').trim().lowercase()
    if (type in DANGEROUS_TYPES) out += Finding(Severity.CRITICAL, "Final page is an app/installer download ($type).")
    val disposition = hop.disposition.lowercase()
    if ("attachment" in disposition) {
        val name = if ("filename=" in disposition) disposition.substringAfter("filename=").trim('"', ';', ' ') else ""
        val ext = if ('.' in name) name.substringAfterLast('.') else ""
        if (ext in DANGEROUS_EXTENSIONS) {
            out += Finding(Severity.CRITICAL, "Final page forces a download of '$name'.")
        } else {
            out += Finding(Severity.MEDIUM, "Final page forces a file download.")
        }
    }
}
