package io.github.scannerip.app

import android.content.Context
import IPtProxy.Controller
import IPtProxy.IPtProxy
import IPtProxy.OnTransportEvents
import io.github.scannerip.core.BridgeType
import io.github.scannerip.core.Bridges
import java.io.File
import java.util.Collections

/**
 * The pluggable transports (obfs4, Snowflake and meek), running inside the app.
 *
 * They come from IPtProxy, the Guardian Project's packaging of the Tor
 * Project's own Lyrebird and Snowflake clients, which is what Orbot uses too.
 * Each one listens on a local port, and Tor is told to reach its bridges
 * through that port. Nothing here is loaded until a bridge is actually needed.
 */
class Transports(private val context: Context) : OnTransportEvents {
    private val running: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())

    private val controller: Controller by lazy {
        val dir = File(context.noBackupFilesDir, "pt_state").apply { mkdirs() }
        IPtProxy.newController(dir.absolutePath, false, false, "ERROR", this)
    }

    /** Start the transport for [type] (if it isn't already) and return its local port. */
    fun start(type: BridgeType): Int {
        val name = methodName(type)
        if (type == BridgeType.SNOWFLAKE) {
            // Snowflake finds its volunteer proxies through a broker; the bridge line says where.
            val options = Bridges.options(Bridges.BUILT_IN.getValue(type).first())
            controller.snowflakeBrokerUrl = options["url"].orEmpty()
            controller.snowflakeFrontDomains = options["fronts"].orEmpty()
            controller.snowflakeIceServers = options["ice"].orEmpty()
            options["ampcache"]?.let { controller.snowflakeAmpCacheUrl = it }
            options["sqsqueue"]?.let { controller.snowflakeSqsUrl = it }
            options["sqscreds"]?.let { controller.snowflakeSqsCreds = it }
        }
        if (name !in running) {
            controller.start(name, "")
            running += name
        }
        return controller.port(name).toInt()
    }

    /** Stop every transport apart from [keep], which may be [BridgeType.NONE] to stop them all. */
    fun stopAllExcept(keep: BridgeType) {
        val wanted = keep.transport
        for (name in running.toList()) {
            if (name != wanted) {
                controller.stop(name)
                running -= name
            }
        }
    }

    private fun methodName(type: BridgeType): String = when (type) {
        BridgeType.OBFS4 -> IPtProxy.Obfs4
        BridgeType.SNOWFLAKE -> IPtProxy.Snowflake
        BridgeType.MEEK -> IPtProxy.MeekLite
        BridgeType.NONE -> throw IllegalArgumentException("no transport needed")
    }

    override fun connected(name: String?) {}

    override fun error(name: String?, error: Exception?) {}

    override fun stopped(name: String?, error: Exception?) {
        name?.let { running -= it }
    }
}
