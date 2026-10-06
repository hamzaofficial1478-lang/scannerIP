package io.github.scannerip.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.scannerip.app.ScanResult
import io.github.scannerip.core.Proceed
import io.github.scannerip.core.SAMPLES
import io.github.scannerip.core.Sample
import io.github.scannerip.core.makeVisible

/** Paste or type anything to check it, or try the built-in demo codes. */
@Composable
fun CheckScreen(
    lastScan: ScanResult?,
    canInspect: Boolean,
    inspecting: Boolean,
    onCheck: (String) -> Unit,
    onSample: (Sample) -> Unit,
    onInspect: (String) -> Unit,
    onCopy: (String) -> Unit,
    onProceed: (Proceed) -> Unit = {},
    onOpenInBrowser: (String) -> Unit = {},
) {
    var text by rememberSaveable { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Check a link or any text", style = MaterialTheme.typography.titleLarge)
        Text("Got a link from a message or a code you've already scanned elsewhere? Paste it here. " +
            "It's only read and checked, never opened.")
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text("Link or text") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 2,
        )
        Button(onClick = { onCheck(text) }, enabled = text.isNotBlank()) { Text("Check it") }

        lastScan?.let { ResultCard(it, canInspect, inspecting, onInspect, onCopy, onProceed, onOpenInBrowser) }

        Text("Demo codes", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 8.dp))
        Text("The same set as the desktop version's samples folder, from harmless to nasty. " +
            "None of them lead anywhere real. Tap one to check it.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SectionCard {
            SAMPLES.forEachIndexed { i, sample ->
                if (i > 0) HorizontalDivider()
                Row(
                    Modifier.fillMaxWidth().clickable { onSample(sample) }.padding(vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(sample.name, style = MaterialTheme.typography.bodyLarge)
                        Text(makeVisible(sample.text).replace('\n', ' '), maxLines = 1, overflow = TextOverflow.Ellipsis,
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}
