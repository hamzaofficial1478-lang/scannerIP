package io.github.scannerip.core

/*
 * Bridges: hidden ways into Tor for networks that block it.
 *
 * Some networks (schools, offices, whole countries) block Tor. They either
 * block the public list of Tor relays or spot what Tor traffic looks like and
 * cut it off. When that happens Tor gets stuck early on, usually around 10%
 * ("connected to a relay" but the handshake never finishes). A bridge is an
 * unlisted way in, and a "pluggable transport" disguises the traffic to it:
 *
 *   obfs4      scrambles it so it looks like random noise
 *   Snowflake  hides it inside WebRTC (video-call style) traffic, relayed
 *              through volunteers' browsers
 *   meek       makes it look like ordinary HTTPS to a big content network
 *
 * The bridge lines below are Tor Browser's own built-in ones, copied from
 * tor-browser-build, projects/tor-expert-bundle/pt_config.json (last changed
 * in commit 01d3e9d35aab, 9 April 2026). Built-in bridges are public, so a
 * determined censor can block them too. If that happens, Orbot or
 * https://bridges.torproject.org can hand out private ones.
 */

enum class BridgeType(val title: String, val transport: String?, val blurb: String) {
    NONE("No bridge", null, "Straight into Tor. Fastest, when it isn't blocked."),
    OBFS4("obfs4", "obfs4", "Looks like random noise. Fast, and Tor Browser's first choice."),
    SNOWFLAKE("Snowflake", "snowflake", "Hides in video-call style traffic. Slower, but very hard to block."),
    MEEK("meek", "meek_lite", "Looks like normal web traffic to a big network. Slow, a last resort."),
}

object Bridges {
    val BUILT_IN: Map<BridgeType, List<String>> = mapOf(
        BridgeType.OBFS4 to listOf(
            "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
            "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
            "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
            "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
            "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
            "obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
            "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
        ),
        BridgeType.SNOWFLAKE to listOf(
            "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
            "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
        ),
        BridgeType.MEEK to listOf(
            "meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN",
        ),
    )

    /**
     * Tor settings, as "Key value" pairs for SETCONF, that send Tor in through
     * [type]. The transport itself runs inside the app and listens on [ptPort].
     */
    fun torConfig(type: BridgeType, ptPort: Int, lines: List<String> = BUILT_IN[type].orEmpty()): List<String> {
        val transport = type.transport ?: return listOf("UseBridges 0")
        require(ptPort in 1..65535) { "no port for the $transport transport" }
        require(lines.isNotEmpty()) { "no $transport bridges" }
        return listOf("UseBridges 1", "ClientTransportPlugin $transport socks5 127.0.0.1:$ptPort") +
            lines.map { "Bridge $it" }
    }

    /** The key=value options on a bridge line, such as url=, fronts= and ice=. */
    fun options(line: String): Map<String, String> =
        line.trim().split(Regex("\\s+")).filter { '=' in it }
            .associate { it.substringBefore('=') to it.substringAfter('=') }

    /**
     * The order automatic mode tries things in: straight in, then each bridge.
     * Whatever got through last time goes first, so a blocked network only
     * has to be worked out once.
     */
    fun autoOrder(lastWorking: BridgeType?): List<BridgeType> {
        val base = listOf(BridgeType.NONE, BridgeType.OBFS4, BridgeType.SNOWFLAKE, BridgeType.MEEK)
        return if (lastWorking == null) base else listOf(lastWorking) + (base - lastWorking)
    }

    /** How long to wait with no progress before trying the next way in. */
    fun patienceMillis(type: BridgeType): Long = when (type) {
        BridgeType.NONE -> 30_000
        BridgeType.OBFS4 -> 45_000
        BridgeType.SNOWFLAKE -> 90_000
        BridgeType.MEEK -> 120_000
    }
}

/**
 * Notices when Tor's start-up has stopped moving. Progress that keeps
 * creeping up, however slowly, never counts as stuck.
 */
class StallWatch(private val patienceMillis: Long, private val now: () -> Long = System::currentTimeMillis) {
    private var best = -1
    private var since = now()

    fun reset() {
        best = -1
        since = now()
    }

    /** Feed in the latest progress (0-100). True once it hasn't gone up for a while. */
    fun stalled(progress: Int): Boolean {
        val t = now()
        if (progress > best) {
            best = progress
            since = t
        }
        return progress < 100 && t - since >= patienceMillis
    }
}
