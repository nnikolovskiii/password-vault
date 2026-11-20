package com.nnikolovskii.vault.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.PhonelinkLock
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material.icons.outlined.ReportProblem
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.nnikolovskii.vault.data.BiometricStatus
import com.nnikolovskii.vault.domain.PassphraseRules

@Composable
fun LoadingScreen() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
internal fun LockColumn(content: @Composable () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        content()
    }
}

@Composable
internal fun Heading(icon: ImageVector, title: String) {
    Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(56.dp))
    Spacer(Modifier.height(16.dp))
    Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
    Spacer(Modifier.height(12.dp))
}

// --- Create ----------------------------------------------------------------------------------

@Composable
fun CreateScreen(model: VaultViewModel, ui: CreateUi) {
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { model.refreshDeviceSecure() }

    if (!ui.deviceSecure) {
        LockColumn {
            Heading(Icons.Outlined.PhonelinkLock, "Set a screen lock first")
            Text(
                "Set a screen lock on the phone first (PIN, pattern, or password). The vault's " +
                    "device key only works while the phone is unlocked, and that is what stops " +
                    "a stolen phone's files from being attacked.",
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
            OutlinedButton(onClick = model::refreshDeviceSecure) { Text("Check again") }
        }
        return
    }

    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var acknowledged by remember { mutableStateOf(false) }
    val check = PassphraseRules.check(passphrase, confirm, acknowledged)

    LockColumn {
        Heading(Icons.Outlined.Lock, "Create your vault")
        Text(
            "Only you can open this vault. Your passphrase never leaves this phone and is never " +
                "stored. There is no recovery: if you forget it, the vault is gone.",
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))
        VaultField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = "Passphrase",
            secret = true,
            enabled = !ui.busy,
            supportingText = "Tip: 4 or more random words.",
        )
        Spacer(Modifier.height(8.dp))
        VaultField(
            value = confirm,
            onValueChange = { confirm = it },
            label = "Confirm passphrase",
            secret = true,
            enabled = !ui.busy,
            imeAction = ImeAction.Done,
        )
        Spacer(Modifier.height(12.dp))
        RuleLine(check.longEnough, "At least ${PassphraseRules.MIN_CODE_POINTS} characters")
        RuleLine(check.matches, "Both entries match")
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Checkbox(checked = acknowledged, onCheckedChange = { acknowledged = it }, enabled = !ui.busy)
            Text("There is no recovery. If I forget this passphrase, the vault is gone.")
        }
        Spacer(Modifier.height(20.dp))
        if (ui.busy) {
            CircularProgressIndicator()
            Spacer(Modifier.height(12.dp))
            Text("Securing your vault…", color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Button(
                onClick = {
                    model.createVault(passphrase, confirm, acknowledged)
                    passphrase = ""
                    confirm = ""
                },
                enabled = check.ok,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Create vault") }
        }
        ui.error?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
        if (!ui.busy) {
            Spacer(Modifier.height(32.dp))
            Text(
                "Have a backup (.pvault) from this or another phone?",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = model::startRestore, modifier = Modifier.fillMaxWidth()) {
                Text("Restore from backup")
            }
        }
    }
}

@Composable
internal fun RuleLine(ok: Boolean, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Icon(
            if (ok) Icons.Outlined.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
            contentDescription = null,
            tint = if (ok) Sage else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
        )
        Spacer(Modifier.width(8.dp))
        Text(text, color = if (ok) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// --- Unlock ----------------------------------------------------------------------------------

@Composable
fun UnlockScreen(model: VaultViewModel, ui: UnlockUi) {
    val biometric by model.biometric.collectAsState()
    var passphrase by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    val blocked = ui.backoffRemainingMillis > 0
    val submit = {
        if (!ui.busy && !blocked && passphrase.isNotEmpty()) {
            model.unlock(passphrase)
            passphrase = ""
        }
    }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }

    LockColumn {
        Spacer(Modifier.height(32.dp))
        Heading(Icons.Outlined.Lock, "Vault is locked")
        Spacer(Modifier.height(12.dp))
        VaultField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = "Passphrase",
            secret = true,
            enabled = !ui.busy,
            imeAction = ImeAction.Done,
            onDone = submit,
            isError = ui.message != null,
            modifier = Modifier.focusRequester(focus),
        )
        Spacer(Modifier.height(16.dp))
        when {
            ui.busy -> CircularProgressIndicator()
            blocked -> Text(
                "Too many attempts. Try again in ${formatCountdown(ui.backoffRemainingMillis)}.",
                color = MaterialTheme.colorScheme.error,
                textAlign = TextAlign.Center,
            )
            else -> Button(
                onClick = submit,
                enabled = passphrase.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Unlock") }
        }
        if (ui.message != null && !ui.busy) {
            Spacer(Modifier.height(12.dp))
            Text(ui.message, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
        }
        // Biometric works during a passphrase backoff: it is not a passphrase guess.
        if (!ui.busy) {
            when (biometric) {
                BiometricStatus.Ready -> {
                    Spacer(Modifier.height(16.dp))
                    OutlinedButton(onClick = model::unlockWithBiometric, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Outlined.Fingerprint, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Unlock with biometrics")
                    }
                }
                BiometricStatus.PassphraseDue -> {
                    Spacer(Modifier.height(16.dp))
                    Text(
                        "Biometric unlock needs your passphrase once every 7 days. It works again after this unlock.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                }
                BiometricStatus.Off, BiometricStatus.Invalidated -> Unit
            }
        }
        ui.debugTiming?.let {
            Spacer(Modifier.height(24.dp))
            Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

internal fun formatCountdown(millis: Long): String {
    val total = (millis + 999) / 1000
    return "%d:%02d".format(total / 60, total % 60)
}

// --- Device key lost -------------------------------------------------------------------------

@Composable
fun DeviceKeyLostScreen(model: VaultViewModel) {
    LockColumn {
        Spacer(Modifier.height(32.dp))
        Heading(Icons.Outlined.ReportProblem, "This phone's vault key is gone")
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                "The vault is protected by your passphrase and by a hardware key that exists " +
                    "only on this phone. That hardware key is missing or was invalidated (this " +
                    "can happen after removing the screen lock or resetting the phone's security).",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Without it, no passphrase can open this vault here. Nothing has been deleted.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Restore from a backup (.pvault) with the passphrase it was made with. If the " +
                    "backup is of this same vault, the entries on this phone are kept, including " +
                    "ones added after the backup.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Do not uninstall the app: that deletes the vault files for good.",
                color = MaterialTheme.colorScheme.error,
            )
        }
        Spacer(Modifier.height(24.dp))
        Button(onClick = model::startRestore, modifier = Modifier.fillMaxWidth()) {
            Text("Restore from backup")
        }
    }
}
