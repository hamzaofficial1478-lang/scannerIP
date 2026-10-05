package io.github.scannerip.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.ConnectionPool
import okhttp3.CookieJar
import okhttp3.Credentials
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/** Where traffic leaves from: a SOCKS5 proxy (Tor, Orbot, ...) or an HTTP proxy. */
sealed class Route {
    abstract val host: String
    abstract val port: Int

    data class Socks(override val host: String, override val port: Int,
                     val username: String? = null, val password: String? = null) : Route()

    data class Http(override val host: String, override val port: Int,
                    val username: String? = null, val password: String? = null) : Route()

    companion object {
        /** "socks5h://user:pass@host:1080", "socks5://host:1080", "http://host:8080" or plain "host:8080". */
        fun parse(text: String): Route {
            val url = text.trim().let { if ("://" in it) it else "http://$it" }
            val parts = UrlParts.split(url)
            val host = parts.hostname ?: throw IllegalArgumentException("No host in '$text'")
            val userInfo = parts.netloc.substringBeforeLast('@', "")
            val user = userInfo.substringBefore(':').ifEmpty { null }?.let(::percentDecode)
            val pass = if (':' in userInfo) percentDecode(userInfo.substringAfter(':')) else null
            return when (parts.scheme) {
                "socks5", "socks5h", "socks" -> Socks(host, parts.port ?: 1080, user, pass)
                "http", "https" -> Http(host, parts.port ?: 8080, user, pass)
                else -> throw IllegalArgumentException("Unsupported proxy type '${parts.scheme}'")
            }
        }
    }
}

data class ExitLookup(val ip: String, val isTor: Boolean?)

object Net {
    val IP_CHECK_URLS = listOf(
        "https://check.torproject.org/api/ip", // {"IsTor": true, "IP": "..."}
        "https://api.ipify.org?format=json",   // {"ip": "..."}
    )

    /**
     * A client that sends everything through [route]. No cookies, no cache, no
     * automatic redirects, and no connection reuse between shifts.
     */
    fun client(route: Route, timeoutSeconds: Long = 20): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS))
            .cookieJar(CookieJar.NO_COOKIES)
            .cache(null)
            .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .callTimeout(timeoutSeconds * 2, TimeUnit.SECONDS)
        when (route) {
            is Route.Socks -> builder
                .proxy(Proxy.NO_PROXY)
                .socketFactory(Socks5SocketFactory(route.host, route.port, route.username, route.password))
                .dns(NoLocalDns)
            is Route.Http -> {
                // An HTTP proxy is handed the site's name too, so no local lookup.
                builder.proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(route.host, route.port)))
                if (route.username != null) {
                    val credentials = Credentials.basic(route.username, route.password.orEmpty())
                    builder.proxyAuthenticator { _, response ->
                        response.request.newBuilder().header("Proxy-Authorization", credentials).build()
                    }
                }
            }
        }
        return builder.build()
    }

    /** Ask a public "what's my IP" service which address it sees us coming from. */
    fun lookupExitIp(route: Route, urls: List<String> = IP_CHECK_URLS, timeoutSeconds: Long = 20): ExitLookup {
        val client = client(route, timeoutSeconds)
        var lastError: Exception? = null
        for (url in urls) {
            try {
                client.newCall(Request.Builder().url(url).build()).execute().use { response ->
                    if (!response.isSuccessful) throw java.io.IOException("HTTP ${response.code}")
                    val data = Json.parseToJsonElement(response.body!!.string()) as JsonObject
                    val ip = (data["IP"] ?: data["ip"])?.jsonPrimitive?.contentOrNull
                    val bytes = ip?.let { IpLiteral.parse(it) } ?: throw java.io.IOException("No IP in answer")
                    return ExitLookup(IpLiteral.format(bytes), data["IsTor"]?.jsonPrimitive?.booleanOrNull)
                }
            } catch (e: Exception) {
                lastError = e // try the next service
            }
        }
        throw RotationError("Couldn't find out the exit IP: ${lastError?.message}", lastError)
    }
}
