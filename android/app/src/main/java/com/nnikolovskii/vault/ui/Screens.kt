package com.nnikolovskii.vault.ui

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.ContextWrapper
import android.os.CancellationSignal
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Password
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.SearchOff
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.ReportProblem
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.nnikolovskii.vault.domain.EntryRow
import com.nnikolovskii.vault.domain.EntrySummary
import com.nnikolovskii.vault.domain.Tags
import com.nnikolovskii.vault.session.SessionState
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

@Composable
fun VaultRoot(model: VaultViewModel) {
    val session by model.session.collectAsState()
    val restore by model.restore.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(model) {
        model.snackbar.collect { snackbar.showSnackbar(it) }
    }

    // SAF pickers at the root: always composed, so a lock while picking does not drop the result.
    val saveBackup = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri -> model.onBackupDestination(uri) }
    val openBackup = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        model.onBackupPicked(uri)
    }
    LaunchedEffect(model) {
        model.pickers.collect { request ->
            try {
                when (request) {
                    is PickerRequest.SaveBackup -> saveBackup.launch(request.fileName)
                    PickerRequest.OpenBackup -> openBackup.launch(arrayOf("*/*"))
                }
            } catch (e: ActivityNotFoundException) {
                if (request is PickerRequest.SaveBackup) model.onBackupDestination(null)
                snackbar.showSnackbar("No file picker on this phone")
            }
        }
    }

    // The system biometric prompt. The ViewModel prepares the cipher; the answer goes back to it.
    val activity = LocalContext.current.findActivity()
    val showing = remember { arrayOfNulls<CancellationSignal>(1) }
    DisposableEffect(Unit) { onDispose { showing[0]?.cancel() } }
    LaunchedEffect(model) {
        model.biometricPrompts.collect { request ->
            val stale = request is BiometricRequest.Unlock && model.session.value != SessionState.Locked
            if (activity == null || stale) {
                model.onBiometricResult(request, BiometricResult.Cancelled)
                return@collect
            }
            showing[0]?.cancel()
            val cancel = CancellationSignal().also { showing[0] = it }
            val (title, negative) = when (request) {
                is BiometricRequest.Unlock -> "Unlock Vault" to "Use passphrase"
                is BiometricRequest.Enable -> "Turn on biometric unlock" to "Cancel"
            }
            BiometricSupport.prompt(activity, title, negative, request.cipher, cancel) { result ->
                if (showing[0] === cancel) showing[0] = null
                model.onBiometricResult(request, result)
            }
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { _ ->
        when (session) {
            SessionState.Loading -> LoadingScreen()
            SessionState.NoVault -> restore?.let { RestoreScreen(model, it) }
                ?: CreateScreen(model, model.create.collectAsState().value)
            SessionState.Locked, SessionState.Unlocking ->
                UnlockScreen(model, model.unlock.collectAsState().value)
            SessionState.DeviceKeyLost -> restore?.let { RestoreScreen(model, it) }
                ?: DeviceKeyLostScreen(model)
            SessionState.Unlocked -> UnlockedContent(model)
        }
    }
}

@Composable
private fun UnlockedContent(model: VaultViewModel) {
    val screen by model.screen.collectAsState()
    when (val s = screen) {
        Screen.List -> ListScreen(model)
        is Screen.Detail -> DetailScreen(model, s.id)
        is Screen.Edit -> EditScreen(model)
        Screen.Export -> ExportScreen(model)
        Screen.ChangePassphrase -> ChangePassphraseScreen(model)
        Screen.Settings -> SettingsScreen(model)
    }
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

// --- List ------------------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ListScreen(model: VaultViewModel) {
    val rows by model.rows.collectAsState()
    val visible by model.visibleRows.collectAsState()
    val query by model.query.collectAsState()
    val tagFilter by model.tagFilter.collectAsState()
    val tags by model.tagsInUse.collectAsState()
    val backup by model.backup.collectAsState()
    var damaged by remember { mutableStateOf<String?>(null) }
    var menu by remember { mutableStateOf(false) }
    val filtering = query.isNotEmpty() || tagFilter != null

    BackHandler(enabled = filtering) { model.clearFilter() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vault") },
                actions = {
                    IconButton(onClick = model::lock) { Icon(Icons.Outlined.Lock, contentDescription = "Lock") }
                    Box {
                        IconButton(onClick = { menu = true }) {
                            Icon(Icons.Outlined.MoreVert, contentDescription = "More")
                        }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(
                                text = { Text("Export backup") },
                                onClick = {
                                    menu = false
                                    model.startExport()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Change passphrase") },
                                onClick = {
                                    menu = false
                                    model.startChangePassphrase()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Settings") },
                                onClick = {
                                    menu = false
                                    model.startSettings()
                                },
                            )
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = model::startAdd) {
                Icon(Icons.Outlined.Add, contentDescription = "Add entry")
            }
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            BackupHeader(backup, onExport = model::startExport)
            if (rows.isNotEmpty()) {
                SearchField(query, model::setQuery)
                // The selected tag stays visible even if its last entry just lost it.
                val chips = tags + listOfNotNull(tagFilter?.takeIf { f -> tags.none { Tags.sameTag(it, f) } })
                if (chips.isNotEmpty()) {
                    LazyRow(
                        contentPadding = PaddingValues(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(chips, key = { it }) { tag ->
                            FilterChip(
                                selected = tagFilter?.let { Tags.sameTag(it, tag) } == true,
                                onClick = { model.toggleTagFilter(tag) },
                                label = { Text(tag, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            )
                        }
                    }
                }
            }
            if (rows.isEmpty()) {
                EmptyState(Modifier)
            } else if (visible.isEmpty() && filtering) {
                NoMatches(onClear = model::clearFilter)
            } else {
                LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(bottom = 96.dp),
                ) {
                    items(visible, key = { it.id }) { row ->
                        when (row) {
                            is EntryRow.Ok -> EntryListRow(
                                row.summary,
                                onOpen = { model.open(row.id) },
                                onCopy = { model.copyPassword(row.id) },
                            )
                            is EntryRow.Damaged -> DamagedRow(onClick = { damaged = row.id })
                        }
                        HorizontalDivider(color = MaterialTheme.colorScheme.outline)
                    }
                }
            }
        }
    }

    damaged?.let { id ->
        ConfirmDelete(
            text = "This entry cannot be decrypted. It was moved, edited, or belongs to another vault. Delete it?",
            onConfirm = {
                model.delete(id)
                damaged = null
            },
            onDismiss = { damaged = null },
        )
    }
}

/** Filters the decrypted list in memory. Plain String state in the ViewModel, never saveable. */
@Composable
private fun SearchField(query: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = query,
        onValueChange = onChange,
        placeholder = { Text("Search") },
        leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
        trailingIcon = if (query.isNotEmpty()) {
            { IconButton(onClick = { onChange("") }) { Icon(Icons.Outlined.Close, contentDescription = "Clear search") } }
        } else {
            null
        },
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.None,
            autoCorrectEnabled = false,
            imeAction = ImeAction.Search,
        ),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
    )
}

@Composable
private fun NoMatches(onClear: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Outlined.SearchOff, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(48.dp))
        Spacer(Modifier.height(12.dp))
        Text("No matching entries", color = MaterialTheme.colorScheme.onSurfaceVariant)
        TextButton(onClick = onClear) { Text("Clear search") }
    }
}

@Composable
private fun EntryListRow(summary: EntrySummary, onOpen: () -> Unit, onCopy: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .padding(start = 20.dp, end = 8.dp, top = 12.dp, bottom = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(summary.title, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (summary.username.isNotEmpty()) {
                Text(
                    summary.username,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        IconButton(onClick = onCopy) {
            Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy password")
        }
    }
}

@Composable
private fun DamagedRow(onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 20.dp, vertical = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Outlined.ReportProblem, contentDescription = null, tint = MaterialTheme.colorScheme.error)
        Spacer(Modifier.size(12.dp))
        Text("Damaged entry", color = MaterialTheme.colorScheme.error)
    }
}

@Composable
private fun EmptyState(modifier: Modifier) {
    Column(
        modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Outlined.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(72.dp))
        Spacer(Modifier.height(16.dp))
        Text("No entries yet", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text("Tap + to add your first login.", color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// --- Detail ----------------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DetailScreen(model: VaultViewModel, id: String) {
    val detail by model.detail.collectAsState()
    var menu by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }

    BackHandler { model.back() }
    // Re-mask when leaving the screen or the app.
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) { model.hideSecrets() }

    val summary = (detail.row as? EntryRow.Ok)?.summary
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(summary?.title ?: "", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = {
                    IconButton(onClick = model::back) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (summary != null) {
                        IconButton(onClick = { model.startEdit(id) }) {
                            Icon(Icons.Outlined.Edit, contentDescription = "Edit")
                        }
                    }
                    Box {
                        IconButton(onClick = { menu = true }) {
                            Icon(Icons.Outlined.MoreVert, contentDescription = "More")
                        }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(
                                text = { Text("Delete") },
                                onClick = {
                                    menu = false
                                    confirmDelete = true
                                },
                            )
                        }
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
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp),
        ) {
            when (val row = detail.row) {
                null -> Unit
                is EntryRow.Damaged -> Text("Damaged entry", color = MaterialTheme.colorScheme.error)
                is EntryRow.Ok -> {
                    val s = row.summary
                    DetailField("Username", s.username.ifEmpty { "—" }) {
                        if (s.username.isNotEmpty()) CopyButton { model.copyField("Username", s.username) }
                    }
                    DetailField(
                        "Password",
                        detail.password?.ifEmpty { "(empty)" } ?: "••••••••",
                        monospace = detail.password != null,
                    ) {
                        IconButton(onClick = model::togglePassword) {
                            Icon(
                                if (detail.password != null) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                contentDescription = if (detail.password != null) "Hide password" else "Reveal password",
                            )
                        }
                        CopyButton { model.copyPassword(id) }
                    }
                    DetailField("URL", s.url.ifEmpty { "—" }) {
                        if (s.url.isNotEmpty()) CopyButton { model.copyField("URL", s.url) }
                    }
                    if (s.tags.isNotEmpty()) TagChips(s.tags, onTag = model::filterByTag)
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = model::toggleNotes) {
                        Text(if (detail.notes != null) "Hide notes" else "Show notes")
                    }
                    detail.notes?.let {
                        Text(
                            it.ifEmpty { "No notes" },
                            color = if (it.isEmpty()) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                        )
                    }
                    Spacer(Modifier.height(24.dp))
                    Meta("Created", s.createdAt)
                    Meta("Updated", s.updatedAt)
                }
            }
        }
    }

    if (confirmDelete) {
        ConfirmDelete(
            text = "Delete this entry? This cannot be undone.",
            onConfirm = {
                confirmDelete = false
                model.delete(id)
            },
            onDismiss = { confirmDelete = false },
        )
    }
}

@Composable
private fun DetailField(
    label: String,
    value: String,
    monospace: Boolean = false,
    actions: @Composable () -> Unit,
) {
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                value,
                fontFamily = if (monospace) FontFamily.Monospace else null,
                style = MaterialTheme.typography.bodyLarge,
            )
        }
        actions()
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outline)
}

/** Tapping a tag shows the list filtered to it. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TagChips(tags: List<String>, onTag: (String) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Text("Tags", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            tags.forEach { tag -> AssistChip(onClick = { onTag(tag) }, label = { Text(tag) }) }
        }
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outline)
}

@Composable
private fun CopyButton(onClick: () -> Unit) {
    IconButton(onClick = onClick) { Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy") }
}

private val dateFormat: DateTimeFormatter =
    DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)

@Composable
private fun Meta(label: String, epochMillis: Long) {
    val text = Instant.ofEpochMilli(epochMillis).atZone(ZoneId.systemDefault()).format(dateFormat)
    Text(
        "$label $text",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun ConfirmDelete(text: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Delete entry") },
        text = { Text(text) },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text("Delete", color = MaterialTheme.colorScheme.error) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

// --- Add / Edit ------------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EditScreen(model: VaultViewModel) {
    val form by model.edit.collectAsState()
    val generator by model.generator.collectAsState()
    val tagsInUse by model.tagsInUse.collectAsState()
    val f = form ?: return
    var confirmDiscard by remember { mutableStateOf(false) }
    val leave = { if (f.dirty) confirmDiscard = true else model.back() }

    BackHandler { leave() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (f.id == null) "New entry" else "Edit entry") },
                navigationIcon = {
                    IconButton(onClick = leave) { Icon(Icons.Outlined.Close, contentDescription = "Cancel") }
                },
                actions = {
                    TextButton(onClick = model::save, enabled = f.canSave) { Text("Save") }
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
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            VaultField(f.title, { v -> model.updateForm { it.with(title = v) } }, "Title")
            VaultField(f.username, { v -> model.updateForm { it.with(username = v) } }, "Username", keyboardType = KeyboardType.Email)
            VaultField(f.password, { v -> model.updateForm { it.with(password = v) } }, "Password", secret = true)
            TextButton(onClick = model::openGenerator) {
                Icon(Icons.Outlined.Password, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.size(8.dp))
                Text("Generate password")
            }
            VaultField(f.url, { v -> model.updateForm { it.with(url = v) } }, "URL", keyboardType = KeyboardType.Uri)
            VaultField(
                f.tags,
                { v -> model.updateForm { it.with(tags = v) } },
                "Tags",
                supportingText = "Separate with commas",
            )
            TagSuggestions(f.tags, tagsInUse, onAdd = model::addTag)
            VaultField(
                f.notes,
                { v -> model.updateForm { it.with(notes = v) } },
                "Notes",
                singleLine = false,
                minLines = 4,
                imeAction = ImeAction.Default,
            )
            f.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        }
    }

    generator?.let { GeneratorDialog(model, it) }

    if (confirmDiscard) {
        AlertDialog(
            onDismissRequest = { confirmDiscard = false },
            title = { Text("Discard changes?") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDiscard = false
                    model.back()
                }) { Text("Discard") }
            },
            dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text("Keep editing") } },
        )
    }
}

/** Tags used elsewhere in the vault that this entry does not have yet. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TagSuggestions(typed: String, inUse: List<String>, onAdd: (String) -> Unit) {
    val current = Tags.parse(typed)
    val missing = inUse.filter { t -> current.none { Tags.sameTag(it, t) } }
    if (missing.isEmpty()) return
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        missing.forEach { tag ->
            AssistChip(onClick = { onAdd(tag) }, label = { Text("+ $tag") })
        }
    }
}
