package com.nnikolovskii.vault.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.nnikolovskii.vault.domain.GeneratorOptions
import com.nnikolovskii.vault.domain.VaultSettings
import kotlin.math.roundToInt

// --- Settings --------------------------------------------------------------------------------

@Composable
fun SettingsScreen(model: VaultViewModel) {
    val settings by model.settings.collectAsState()
    val ui by model.settingsUi.collectAsState()
    val biometricOn by model.biometricEnabled.collectAsState()
    val hardware by model.biometricHardware.collectAsState()
    BackHandler { model.back() }
    // Enrolling a fingerprint happens in the phone's settings; check again on return.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { model.refreshBiometricHardware() }

    TaskScaffold("Settings", onBack = model::back) {
        SectionTitle("Unlock")
        BiometricSection(model, ui, biometricOn, hardware)
        HorizontalDivider(color = MaterialTheme.colorScheme.outline)

        SectionTitle("Auto-lock")
        ChoiceRow(
            label = "After leaving the app",
            value = settings.backgroundLockSeconds,
            choices = VaultSettings.BACKGROUND_CHOICES,
            onPick = model::setBackgroundLock,
        )
        ChoiceRow(
            label = "When idle in the app",
            value = settings.idleLockSeconds,
            choices = VaultSettings.IDLE_CHOICES,
            onPick = model::setIdleLock,
        )
        Note("Turning the screen off always locks the vault at once. A lock also clears a copied value.")
        HorizontalDivider(color = MaterialTheme.colorScheme.outline)

        SectionTitle("Clipboard")
        ChoiceRow(
            label = "Clear copied values after",
            value = settings.clipboardClearSeconds,
            choices = VaultSettings.CLIPBOARD_CHOICES,
            onPick = model::setClipboardClear,
        )
        Note("Settings are stored encrypted with the vault. They are not part of a backup.")
    }
}

@Composable
private fun BiometricSection(
    model: VaultViewModel,
    ui: SettingsUi,
    on: Boolean,
    hardware: BiometricSupport.Availability,
) {
    val usable = hardware == BiometricSupport.Availability.Available
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.weight(1f)) {
            Text("Biometric unlock")
            Text(
                when {
                    on -> "On. Your passphrase is still needed every 7 days, and after the phone's fingerprints or face data change."
                    hardware == BiometricSupport.Availability.NoneEnrolled ->
                        "Set up a fingerprint (or face unlock that counts as strong) in the phone's settings first."
                    !usable -> "This phone has no strong biometric sensor."
                    else -> "Fingerprint or face (strong biometrics only) instead of typing the passphrase."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.width(12.dp))
        Switch(
            checked = on || ui.enabling,
            enabled = !ui.busy && (on || usable),
            onCheckedChange = { checked ->
                when {
                    checked -> model.startEnableBiometric()
                    on -> model.disableBiometric()
                    else -> model.cancelEnableBiometric()
                }
            },
        )
    }
    if (ui.enabling && !on) EnableBiometricForm(model, ui)
    ui.message?.takeIf { !ui.enabling || ui.isError }?.let {
        Text(it, color = if (ui.isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** Turning it on proves the passphrase first, then the system prompt confirms the finger. */
@Composable
private fun EnableBiometricForm(model: VaultViewModel, ui: SettingsUi) {
    var passphrase by remember { mutableStateOf("") }
    val submit = {
        if (!ui.busy && passphrase.isNotEmpty()) {
            model.enableBiometric(passphrase)
            passphrase = ""
        }
    }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Enter your passphrase to turn on biometric unlock.")
            VaultField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = "Passphrase",
                secret = true,
                enabled = !ui.busy,
                imeAction = ImeAction.Done,
                onDone = submit,
                isError = ui.isError,
            )
            if (ui.busy) {
                BusyLine("Checking…")
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = submit, enabled = passphrase.isNotEmpty()) { Text("Turn on") }
                    OutlinedButton(onClick = model::cancelEnableBiometric) { Text("Cancel") }
                }
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
}

@Composable
private fun Note(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/** A setting with a fixed list of values: tap, pick one in a dialog. */
@Composable
private fun ChoiceRow(label: String, value: Int, choices: List<Int>, onPick: (Int) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().clickable { open = true }.padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Text(formatSeconds(value), color = MaterialTheme.colorScheme.primary)
    }
    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text(label) },
            text = {
                Column {
                    choices.forEach { c ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .selectable(selected = c == value, role = Role.RadioButton) {
                                    open = false
                                    if (c != value) onPick(c)
                                }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = c == value, onClick = null)
                            Spacer(Modifier.width(12.dp))
                            Text(formatSeconds(c))
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { open = false }) { Text("Cancel") } },
        )
    }
}

// --- Generator -------------------------------------------------------------------------------

/** Over Add / Edit. Every option change makes a new value; "Use" puts it in the password field. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun GeneratorDialog(model: VaultViewModel, ui: GeneratorUi) {
    val o = ui.options
    AlertDialog(
        onDismissRequest = model::closeGenerator,
        title = { Text("Generate") },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = o.mode == GeneratorOptions.Mode.Characters,
                        onClick = { model.updateGenerator { it.copy(mode = GeneratorOptions.Mode.Characters) } },
                        label = { Text("Characters") },
                    )
                    FilterChip(
                        selected = o.mode == GeneratorOptions.Mode.Words,
                        onClick = { model.updateGenerator { it.copy(mode = GeneratorOptions.Mode.Words) } },
                        label = { Text("Words") },
                    )
                }
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                    Row(Modifier.padding(start = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            ui.preview,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.weight(1f).padding(vertical = 12.dp),
                        )
                        IconButton(onClick = model::regenerate) {
                            Icon(Icons.Outlined.Refresh, contentDescription = "Generate another")
                        }
                    }
                }
                Text(
                    "≈ ${ui.bits} bits · ${strength(ui.bits)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                when (o.mode) {
                    GeneratorOptions.Mode.Characters -> {
                        Text("Length ${o.length}")
                        Slider(
                            value = o.length.toFloat(),
                            onValueChange = { v -> model.updateGenerator { it.copy(length = v.roundToInt()) } },
                            valueRange = GeneratorOptions.MIN_LENGTH.toFloat()..GeneratorOptions.MAX_LENGTH.toFloat(),
                            steps = GeneratorOptions.MAX_LENGTH - GeneratorOptions.MIN_LENGTH - 1,
                        )
                        // At least one set stays on.
                        val on = listOf(o.lower, o.upper, o.digits, o.symbols).count { it }
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            SetChip("a–z", o.lower, on) { model.updateGenerator { g -> g.copy(lower = !g.lower) } }
                            SetChip("A–Z", o.upper, on) { model.updateGenerator { g -> g.copy(upper = !g.upper) } }
                            SetChip("0–9", o.digits, on) { model.updateGenerator { g -> g.copy(digits = !g.digits) } }
                            SetChip("!#$", o.symbols, on) { model.updateGenerator { g -> g.copy(symbols = !g.symbols) } }
                        }
                    }
                    GeneratorOptions.Mode.Words -> {
                        Text("${o.words} words")
                        Slider(
                            value = o.words.toFloat(),
                            onValueChange = { v -> model.updateGenerator { it.copy(words = v.roundToInt()) } },
                            valueRange = GeneratorOptions.MIN_WORDS.toFloat()..GeneratorOptions.MAX_WORDS.toFloat(),
                            steps = GeneratorOptions.MAX_WORDS - GeneratorOptions.MIN_WORDS - 1,
                        )
                        Text("Separator", style = MaterialTheme.typography.labelMedium)
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            GeneratorOptions.SEPARATORS.forEach { sep ->
                                FilterChip(
                                    selected = o.separator == sep,
                                    onClick = { model.updateGenerator { it.copy(separator = sep) } },
                                    label = { Text(if (sep == ' ') "space" else sep.toString()) },
                                )
                            }
                        }
                        SwitchLine("Capitalize words", o.capitalize) { model.updateGenerator { g -> g.copy(capitalize = !g.capitalize) } }
                        SwitchLine("Add a digit", o.addDigit) { model.updateGenerator { g -> g.copy(addDigit = !g.addDigit) } }
                        Note("EFF large wordlist, 7 776 words.")
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = model::useGenerated) { Text("Use") } },
        dismissButton = { TextButton(onClick = model::closeGenerator) { Text("Cancel") } },
    )
}

@Composable
private fun SetChip(label: String, selected: Boolean, onCount: Int, onToggle: () -> Unit) {
    FilterChip(
        selected = selected,
        enabled = !selected || onCount > 1,
        onClick = onToggle,
        label = { Text(label) },
    )
}

@Composable
private fun SwitchLine(label: String, checked: Boolean, onToggle: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = { onToggle() })
    }
}

private fun strength(bits: Int): String = when {
    bits >= 100 -> "very strong"
    bits >= 75 -> "strong"
    bits >= 60 -> "fair"
    else -> "weak"
}
