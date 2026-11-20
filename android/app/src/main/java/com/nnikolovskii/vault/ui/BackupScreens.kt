package com.nnikolovskii.vault.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Restore
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.nnikolovskii.vault.domain.PassphraseRules
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

private val backupDate: DateTimeFormatter =
    DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)

private fun formatDate(epochMillis: Long): String =
    Instant.ofEpochMilli(epochMillis).atZone(ZoneId.systemDefault()).format(backupDate)

private fun entryCount(n: Int) = if (n == 1) "1 entry" else "$n entries"

// --- List header -----------------------------------------------------------------------------

/** "Last backup: N days ago", and a reminder card when entries changed and the backup is old. */
@Composable
fun BackupHeader(banner: BackupBanner?, onExport: () -> Unit) {
    banner ?: return
    if (banner.remind) {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("Back up your vault", fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                Text(
                    "${banner.label}. Entries changed since then, and this phone holds the only " +
                        "up-to-date copy. Export an encrypted backup.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                Button(onClick = onExport) { Text("Export backup") }
            }
        }
    } else {
        Text(
            banner.label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp),
        )
    }
}

// --- Export ----------------------------------------------------------------------------------

@Composable
fun ExportScreen(model: VaultViewModel) {
    val ui by model.export.collectAsState()
    BackHandler { model.back() }

    TaskScaffold("Export backup", onBack = model::back) {
        Text(
            "The backup is one encrypted file (.pvault). It holds your entries exactly as they " +
                "are stored here, and opens only with your passphrase, on any phone with Vault. " +
                "It is safe to keep on Drive.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            "Anyone who gets the file can try to guess the passphrase offline, so it is only " +
                "as strong as your passphrase.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        val ready = ui.readyEntries
        if (ready != null) {
            Text("Backup ready · ${entryCount(ready)}. Choose where to save it.")
            Button(onClick = model::chooseExportDestination, modifier = Modifier.fillMaxWidth()) {
                Text("Choose location")
            }
        } else {
            ExportForm(model, ui)
        }
    }
}

@Composable
private fun ExportForm(model: VaultViewModel, ui: PassphraseTaskUi) {
    var passphrase by remember { mutableStateOf("") }
    val submit = {
        if (!ui.busy && passphrase.isNotEmpty()) {
            model.export(passphrase)
            passphrase = ""
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Enter your passphrase to confirm the backup can be opened.")
        VaultField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = "Passphrase",
            secret = true,
            enabled = !ui.busy,
            imeAction = ImeAction.Done,
            onDone = submit,
            isError = ui.message != null,
        )
        if (ui.busy) {
            BusyLine("Preparing the backup…")
        } else {
            Button(onClick = submit, enabled = passphrase.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
                Text("Create backup file")
            }
        }
        ui.message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

// --- Change passphrase -----------------------------------------------------------------------

@Composable
fun ChangePassphraseScreen(model: VaultViewModel) {
    val ui by model.change.collectAsState()
    var current by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var acknowledged by remember { mutableStateOf(false) }
    val check = PassphraseRules.check(new, confirm, acknowledged)
    BackHandler { model.back() }

    TaskScaffold("Change passphrase", onBack = model::back) {
        Text(
            "Entries stay as they are; only the passphrase layer is replaced. Backups made " +
                "before this still open with the old passphrase only, so export a new backup " +
                "afterwards.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        VaultField(
            value = current,
            onValueChange = { current = it },
            label = "Current passphrase",
            secret = true,
            enabled = !ui.busy,
            isError = ui.message != null,
        )
        VaultField(
            value = new,
            onValueChange = { new = it },
            label = "New passphrase",
            secret = true,
            enabled = !ui.busy,
            supportingText = "Tip: 4 or more random words.",
        )
        VaultField(
            value = confirm,
            onValueChange = { confirm = it },
            label = "Confirm new passphrase",
            secret = true,
            enabled = !ui.busy,
            imeAction = ImeAction.Done,
        )
        Column {
            RuleLine(check.longEnough, "At least ${PassphraseRules.MIN_CODE_POINTS} characters")
            RuleLine(check.matches, "Both entries match")
        }
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Checkbox(checked = acknowledged, onCheckedChange = { acknowledged = it }, enabled = !ui.busy)
            Text("There is no recovery. If I forget the new passphrase, the vault is gone.")
        }
        if (ui.busy) {
            BusyLine("Re-securing your vault…")
        } else {
            Button(
                onClick = {
                    model.changePassphrase(current, new, confirm, acknowledged)
                    current = ""
                    new = ""
                    confirm = ""
                },
                enabled = check.ok && current.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Change passphrase") }
        }
        ui.message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

// --- Restore ---------------------------------------------------------------------------------

/** Shown over Create or Device key lost once a `.pvault` file is picked and parsed. */
@Composable
fun RestoreScreen(model: VaultViewModel, ui: RestoreUi) {
    var passphrase by remember { mutableStateOf("") }
    val submit = {
        if (!ui.busy && passphrase.isNotEmpty()) {
            model.restore(passphrase)
            passphrase = ""
        }
    }
    BackHandler(enabled = !ui.busy) { model.cancelRestore() }

    LockColumn {
        Heading(Icons.Outlined.Restore, "Restore from backup")
        Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            Text(
                "Backup from ${formatDate(ui.preview.exportedAt)} · ${entryCount(ui.preview.entryCount)}",
                fontWeight = FontWeight.Medium,
            )
            when {
                ui.preview.keepsPhoneEntries -> Text(
                    "This backup is of the vault on this phone. The entries on the phone are " +
                        "kept as they are; the backup only brings back the key.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                ui.preview.replacesOtherVault -> Text(
                    "This backup is of a different vault. Restoring replaces the vault on this " +
                        "phone, which can no longer be opened.",
                    color = MaterialTheme.colorScheme.error,
                )
                else -> Unit
            }
            Text(
                "Use the passphrase this backup was made with. After restoring, that is the " +
                    "vault's passphrase.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(16.dp))
        VaultField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = "Backup passphrase",
            secret = true,
            enabled = !ui.busy,
            imeAction = ImeAction.Done,
            onDone = submit,
            isError = ui.message != null,
        )
        Spacer(Modifier.height(16.dp))
        if (ui.busy) {
            BusyLine("Restoring…")
        } else {
            Button(onClick = submit, enabled = passphrase.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
                Text("Restore")
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = model::cancelRestore, modifier = Modifier.fillMaxWidth()) {
                Text("Cancel")
            }
        }
        ui.message?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
        }
    }
}

// --- Shared ----------------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TaskScaffold(title: String, onBack: () -> Unit, content: @Composable () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            content()
        }
    }
}

@Composable
internal fun BusyLine(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(Modifier.padding(end = 12.dp))
        Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
