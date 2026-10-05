package io.github.scannerip.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.scannerip.core.Kind
import io.github.scannerip.core.Level
import io.github.scannerip.core.ScanEntry
import io.github.scannerip.core.makeVisible

@Composable
fun HistoryScreen(entries: List<ScanEntry>, onShare: () -> Unit, onClear: () -> Unit) {
    var confirmClear by remember { mutableStateOf(false) }
    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Text("Scan history", style = MaterialTheme.typography.titleLarge)
            Text("Every scan is saved on this phone under the rotating ID that was live at the time, never the " +
                "phone's own ID. If this list ever leaked, the scans couldn't be traced back to you.",
                modifier = Modifier.padding(top = 4.dp))
            Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onShare, enabled = entries.isNotEmpty()) { Text("Share") }
                OutlinedButton(onClick = { confirmClear = true }, enabled = entries.isNotEmpty()) { Text("Clear") }
            }
        }
        if (entries.isEmpty()) {
            item { Text("No scans yet.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
        items(entries) { entry ->
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RiskBadge(Level.entries.find { it.name == entry.level } ?: Level.CLEAN, entry.score, small = true)
                    Spacer(Modifier.width(8.dp))
                    Text(Kind.entries.find { it.name.lowercase() == entry.kind }?.label ?: entry.kind,
                        style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.weight(1f))
                    Text(entry.time, style = MaterialTheme.typography.labelSmall)
                }
                Text(makeVisible(entry.content).replace('\n', ' '), maxLines = 2, overflow = TextOverflow.Ellipsis,
                    fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
                Text("${entry.format} - logged as ${entry.rotatingId ?: "-"}", style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
            }
        }
    }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Clear history?") },
            text = { Text("This deletes every saved scan from this phone. It can't be undone.") },
            confirmButton = { TextButton(onClick = { confirmClear = false; onClear() }) { Text("Clear") } },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("Keep") } },
        )
    }
}
