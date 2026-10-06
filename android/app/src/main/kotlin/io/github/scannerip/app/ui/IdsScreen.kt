package io.github.scannerip.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.scannerip.core.Layer

@Composable
fun IdsScreen(
    layers: List<Layer>,
    keyDescription: String,
    onResetAdId: () -> Unit = {},
    onVerifySeal: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("Device ID layers", style = MaterialTheme.typography.titleLarge)
        Text("Your real device ID never leaves this phone. Everything below is worked out from it in one " +
            "direction only, and the outer layers change every time the IP shifts, so scans can't be " +
            "linked back to you or to each other.")
        layers.forEach { layer ->
            SectionCard {
                Text(layer.name, fontWeight = FontWeight.SemiBold)
                Text(layer.value, fontFamily = FontFamily.Monospace, fontSize = 13.sp, modifier = Modifier.padding(vertical = 4.dp))
                Text(layer.why, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (keyDescription.isNotEmpty()) {
            Text("Keys are kept in: $keyDescription. They can be used by ScannerIP but never copied out of the phone.",
                style = MaterialTheme.typography.bodySmall)
        }
        OutlinedButton(onClick = onVerifySeal) { Text("Prove only this phone can open Layer 1") }

        Text("What about your phone's own IDs?", style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 8.dp))
        SectionCard {
            Text("ScannerIP never sends your phone's IDs anywhere. That's what the layers above are for. It can't " +
                "change them, though, and no app can. The IMEI is built into the phone (and tampering with it is " +
                "against the law in many countries), and Android gives each app its own fixed ID that only a factory " +
                "reset changes.")
            Text("Two that you can change yourself: your advertising ID, which apps and ad networks use to follow you " +
                "from app to app, and your Wi-Fi MAC address, which Android already randomises for each network " +
                "unless you've switched that off in the network's settings.",
                modifier = Modifier.padding(top = 6.dp))
            OutlinedButton(onClick = onResetAdId, modifier = Modifier.padding(top = 8.dp)) {
                Text("Reset or delete my advertising ID")
            }
        }
    }
}
