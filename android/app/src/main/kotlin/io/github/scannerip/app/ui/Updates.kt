package io.github.scannerip.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.scannerip.app.UpdateState

/** Shown on every tab while there's a newer build to install. */
@Composable
fun UpdateBanner(state: UpdateState, onUpdate: () -> Unit, modifier: Modifier = Modifier) {
    val info = when (state) {
        is UpdateState.Available -> state.info
        is UpdateState.Downloading -> state.info
        is UpdateState.Installing -> state.info
        is UpdateState.Failed -> state.info
        else -> null
    } ?: return
    Card(
        modifier = modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("ScannerIP ${info.versionName} is ready", fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onPrimaryContainer)
            if (info.notes.isNotBlank()) {
                Text(info.notes, maxLines = 2, overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onPrimaryContainer)
            }
            when (state) {
                is UpdateState.Available -> Button(onClick = onUpdate, modifier = Modifier.padding(top = 8.dp)) {
                    Text("Update now")
                }
                is UpdateState.Downloading -> {
                    LinearProgressIndicator(progress = { state.progress },
                        modifier = Modifier.fillMaxWidth().padding(top = 10.dp))
                    Text("Downloading ${(state.progress * 100).toInt()}%...",
                        style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 4.dp))
                }
                is UpdateState.Installing -> Text("Checked and verified. Android will ask you to confirm the update.",
                    style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 6.dp))
                is UpdateState.Failed -> {
                    Text(state.message, color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 6.dp))
                    OutlinedButton(onClick = onUpdate, modifier = Modifier.padding(top = 6.dp)) { Text("Try again") }
                }
                else -> {}
            }
        }
    }
}

/** The "App updates" part of the Shield tab. */
@Composable
fun UpdatesCard(
    version: String,
    state: UpdateState,
    backgroundChecks: Boolean,
    onCheck: () -> Unit,
    onBackgroundChecks: (Boolean) -> Unit,
) {
    Text("App updates", style = MaterialTheme.typography.titleMedium)
    SectionCard {
        Text("You have ScannerIP $version", fontWeight = FontWeight.SemiBold)
        val line = when (state) {
            UpdateState.Idle -> "Checks for a new build once the shield connects."
            UpdateState.Checking -> "Checking GitHub for a new build..."
            UpdateState.UpToDate -> "You're on the newest build."
            is UpdateState.Available, is UpdateState.Downloading, is UpdateState.Installing ->
                "A new build is ready - see the banner at the top."
            is UpdateState.Failed -> state.message
        }
        Text(line, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 2.dp))
        val busy = state is UpdateState.Checking || state is UpdateState.Downloading || state is UpdateState.Installing
        OutlinedButton(onClick = onCheck, enabled = !busy, modifier = Modifier.padding(top = 8.dp)) {
            Text("Check for updates")
        }
        Row(Modifier.padding(top = 10.dp), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween) {
            Column(Modifier.weight(1f)) {
                Text("Check in the background")
                Text("About twice a day, even with the app closed, and you get a notification. Tor isn't " +
                    "running then, so that check goes straight to GitHub and GitHub sees your IP.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.width(8.dp))
            Switch(checked = backgroundChecks, onCheckedChange = onBackgroundChecks)
        }
    }
}
