package io.github.scannerip.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.scannerip.app.AppViewModel
import io.github.scannerip.app.BridgeChoice
import io.github.scannerip.app.ShieldMode
import io.github.scannerip.app.ShieldState
import io.github.scannerip.app.ShieldUi
import io.github.scannerip.core.BridgeType
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ShieldScreen(
    state: ShieldUi,
    onMode: (ShieldMode) -> Unit,
    onInterval: (Int) -> Unit,
    onShiftNow: () -> Unit,
    onRetry: () -> Unit,
    onProxyText: (String) -> Unit,
    onStartOrbot: () -> Unit,
    onGetOrbot: () -> Unit,
    onBridges: (BridgeChoice) -> Unit = {},
    onShowOwnIp: () -> Unit = {},
    onSeeItOnAWebsite: () -> Unit = {},
    footer: @Composable () -> Unit = {},
) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        StatusCard(state, onShiftNow, onRetry)
        if (state.mode.anonymous) ProofCard(state, onShowOwnIp, onSeeItOnAWebsite)

        if (state.mode == ShieldMode.DEMO) {
            SectionCard {
                Text("Demo mode", fontWeight = FontWeight.Bold, color = ShieldAmber)
                Text("These addresses are made up (RFC 5737 documentation ranges) and your real IP is NOT hidden. " +
                    "Good for showing how shifting works in class. Use Tor for real protection.")
            }
        }

        Text("How to shift your IP", style = MaterialTheme.typography.titleMedium)
        SectionCard {
            ShieldMode.entries.forEachIndexed { i, mode ->
                if (i > 0) HorizontalDivider()
                Row(
                    Modifier
                        .fillMaxWidth()
                        .selectable(selected = mode == state.mode, onClick = { onMode(mode) }, role = Role.RadioButton)
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    RadioButton(selected = mode == state.mode, onClick = null)
                    Spacer(Modifier.width(8.dp))
                    Column {
                        Text(mode.title, fontWeight = FontWeight.SemiBold)
                        Text(mode.blurb, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }

        if (state.mode == ShieldMode.BUILT_IN_TOR) {
            Text("Getting past blocks", style = MaterialTheme.typography.titleMedium)
            SectionCard {
                val now = when (state.via) {
                    null -> ""
                    BridgeType.NONE -> " Right now Tor is connected directly."
                    else -> " Right now Tor is connected through a ${state.via.title} bridge."
                }
                Text("Some networks block Tor, and then it gets stuck early on (often at 10%). A bridge is a hidden " +
                    "way in that doesn't look like Tor.$now", style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(bottom = 4.dp))
                BridgeChoice.entries.forEachIndexed { i, choice ->
                    if (i > 0) HorizontalDivider()
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(selected = choice == state.bridges, onClick = { onBridges(choice) }, role = Role.RadioButton)
                            .padding(vertical = 6.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        RadioButton(selected = choice == state.bridges, onClick = null)
                        Spacer(Modifier.width(8.dp))
                        Column {
                            Text(if (choice == BridgeChoice.AUTO) "${choice.title} (recommended)" else choice.title,
                                fontWeight = FontWeight.SemiBold)
                            Text(choice.blurb, style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }

        if (state.mode == ShieldMode.ORBOT) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (state.orbotInstalled) Button(onClick = onStartOrbot) { Text("Start Orbot") }
                else Button(onClick = onGetOrbot) { Text("Get Orbot") }
            }
        }

        if (state.mode == ShieldMode.PROXY_LIST) {
            var draft by remember(state.mode) { mutableStateOf(state.proxyText) }
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                label = { Text("Proxies, one per line") },
                placeholder = { Text("socks5h://127.0.0.1:9050\nhttp://proxy.example:8080") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3,
            )
            Button(onClick = { onProxyText(draft); onRetry() }) { Text("Use these proxies") }
        }

        Text("How often", style = MaterialTheme.typography.titleMedium)
        SectionCard {
            var slider by remember(state.mode, state.intervalSeconds) { mutableFloatStateOf(state.intervalSeconds.toFloat()) }
            Text("Shift every ${slider.toInt()} seconds")
            Slider(
                value = slider,
                onValueChange = { slider = it },
                onValueChangeFinished = { onInterval(slider.toInt()) },
                valueRange = state.mode.minInterval.toFloat()..AppViewModel.MAX_INTERVAL.toFloat(),
            )
            if (state.mode == ShieldMode.BUILT_IN_TOR || state.mode == ShieldMode.ORBOT) {
                Text("Every shift builds a new Tor circuit, and the Tor Project asks people not to churn circuits " +
                    "for no reason, so 30 seconds is a kind default and 10 is the floor. The timer pauses while " +
                    "ScannerIP is off screen and shifts as soon as you're back.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        if (state.history.isNotEmpty()) {
            Text("Shift history (IP and ID change together)", style = MaterialTheme.typography.titleMedium)
            SectionCard {
                val clock = remember { SimpleDateFormat("HH:mm:ss", Locale.UK) }
                state.history.forEachIndexed { i, ev ->
                    if (i > 0) HorizontalDivider()
                    Column(Modifier.padding(vertical = 6.dp)) {
                        Row {
                            Text("#${ev.identity.rotation}", fontWeight = FontWeight.Bold, modifier = Modifier.width(48.dp))
                            Text(clock.format(Date(ev.identity.at)), modifier = Modifier.width(76.dp))
                            Text(ev.exit.ip, fontFamily = FontFamily.Monospace)
                        }
                        Text(ev.identity.rotatingId, fontFamily = FontFamily.Monospace, fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 48.dp))
                    }
                }
            }
        }

        footer()
    }
}

@Composable
private fun StatusCard(state: ShieldUi, onShiftNow: () -> Unit, onRetry: () -> Unit) {
    SectionCard {
        val (colour, label) = when (state.state) {
            ShieldState.ACTIVE -> ShieldGreen to "Shield on"
            ShieldState.DEMO -> ShieldAmber to "Demo"
            ShieldState.STARTING -> ShieldGrey to "Connecting"
            ShieldState.ERROR -> ShieldRed to "Shield problem"
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            StatusDot(colour)
            Spacer(Modifier.width(8.dp))
            Text(label, fontWeight = FontWeight.Bold, color = colour)
            Spacer(Modifier.weight(1f))
            Text(state.mode.title, style = MaterialTheme.typography.labelMedium)
        }
        // When the shield isn't working, the last address is only history, so don't present it as live.
        val stale = state.mode.anonymous && state.state != ShieldState.ACTIVE && state.current != null
        Text(
            state.current?.exit?.ip ?: "-",
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 30.sp,
            color = if (stale) MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f) else Color.Unspecified,
            modifier = Modifier.padding(top = 8.dp),
        )
        Text(
            when {
                !state.mode.anonymous -> "A made-up address for the demo. Websites still see your real one."
                stale -> "The last address the shield used. Nothing is going out through it until the shield is back on."
                else -> "This is the address websites see instead of yours."
            },
            style = MaterialTheme.typography.bodySmall,
            color = if (state.mode.anonymous) MaterialTheme.colorScheme.onSurfaceVariant else ShieldAmber,
        )
        Text(state.status, modifier = Modifier.padding(top = 6.dp))
        state.torProgress?.let { progress ->
            LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        }
        Row(Modifier.padding(top = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            state.current?.let { Text("Shift #${it.identity.rotation}", fontWeight = FontWeight.SemiBold) }
            state.secondsLeft?.let { Text("   next in ${it}s") }
            Spacer(Modifier.weight(1f))
            if (state.state == ShieldState.ERROR) OutlinedButton(onClick = onRetry) { Text("Try again") }
            else OutlinedButton(onClick = onShiftNow, enabled = state.current != null) { Text("Shift now") }
        }
    }
}

/**
 * "Is it real?" A fair question when an app says it changes your IP. This
 * shows the phone's own address next to the exit address, and can open a
 * real website that reports which address it sees.
 */
@Composable
private fun ProofCard(state: ShieldUi, onShowOwnIp: () -> Unit, onSeeItOnAWebsite: () -> Unit) {
    SectionCard {
        Text("Is it really changing?", fontWeight = FontWeight.Bold)
        Text("Yes, for everything ScannerIP sends: link checks, pages you open safely and update checks. " +
            "After every shift the app asks check.torproject.org, through the new route, which address it can see, " +
            "and that's the number above. Other apps on your phone still use your normal address.",
            style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp))
        state.ownIp?.let { own ->
            Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Your phone's own IP", modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                Text(own, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold)
            }
            state.current?.exit?.ip?.let { exit ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("What sites see from ScannerIP", modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                    Text(exit, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold)
                }
            }
        }
        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onShowOwnIp, enabled = !state.ownIpBusy) {
                Text(if (state.ownIpBusy) "Checking..." else "Show my own IP")
            }
            OutlinedButton(onClick = onSeeItOnAWebsite, enabled = state.canInspect) { Text("Test on a website") }
        }
        Text("\"Show my own IP\" goes straight out, without the shield, so that one check sees your real address. " +
            "\"Test on a website\" opens check.torproject.org through the shield.",
            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp))
    }
}
