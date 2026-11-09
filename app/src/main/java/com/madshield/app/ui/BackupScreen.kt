package com.madshield.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Backup
import androidx.compose.material.icons.rounded.DataUsage
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.AetherController
import com.madshield.app.core.BackupDoc
import com.madshield.app.core.BackupFile
import com.madshield.app.core.BackupPart
import com.madshield.app.core.BackupRead
import com.madshield.app.core.BackupStore
import com.madshield.app.core.ConnectionState
import com.madshield.app.core.SettingsStore
import com.madshield.app.ui.components.BackTopBar
import com.madshield.app.ui.components.CookieBadge
import com.madshield.app.ui.components.HelperText
import com.madshield.app.ui.components.InfoHint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date
import java.util.Locale

private const val MIN_PASSWORD = 6

/**
 * Backup and restore (update41). The person picks which parts go into ONE file (settings, routing, appearance, usage
 * statistics, and, with a password only, saved links and secrets) and later picks again which parts to bring back.
 * Nothing runs in the background: the page reads and writes only while it is open and a button was pressed.
 */
@Composable
fun BackupScreen(store: SettingsStore, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by AetherController.state.collectAsState()
    val idle = state is ConnectionState.Idle

    var counts by remember { mutableStateOf<Map<BackupPart, Int>?>(null) }
    var chosen by remember { mutableStateOf(setOf(BackupPart.SETTINGS, BackupPart.ROUTING, BackupPart.APPEARANCE, BackupPart.USAGE)) }
    var usePassword by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var found by remember { mutableStateOf<BackupDoc?>(null) }
    var waitingText by remember { mutableStateOf<String?>(null) }
    var wrongPassword by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { counts = withContext(Dispatchers.IO) { BackupStore.summarize(ctx, store) } }

    val passwordOn = usePassword || BackupPart.SECRETS in chosen
    val passwordOk = !passwordOn || password.length >= MIN_PASSWORD
    val canCreate = chosen.isNotEmpty() && passwordOk && !busy

    val invalidMsg = stringResource(R.string.bk_invalid)
    val unreadableMsg = stringResource(R.string.bk_unreadable)
    val savedMsg = stringResource(R.string.bk_saved)
    val saveFailedMsg = stringResource(R.string.bk_save_failed)

    val create = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            busy = true
            val ok = withContext(Dispatchers.IO) {
                val doc = BackupStore.build(ctx, store, chosen)
                BackupStore.writeText(ctx, uri, BackupFile.write(doc, if (passwordOn) password else null))
            }
            busy = false
            message = if (ok) savedMsg else saveFailedMsg
        }
    }

    // Reads the text with the password (when it has one) and moves to the next step. Used for the first try and for each retry.
    suspend fun openText(text: String, pw: String?) {
        when (val r = withContext(Dispatchers.IO) { BackupFile.read(text, pw) }) {
            is BackupRead.Ok -> { found = r.doc; waitingText = null; wrongPassword = false }
            BackupRead.NeedsPassword -> { waitingText = text; wrongPassword = false }
            BackupRead.WrongPasswordOrDamaged -> { waitingText = text; wrongPassword = true }
            BackupRead.Invalid -> { waitingText = null; message = invalidMsg }
        }
    }

    val open = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val text = withContext(Dispatchers.IO) { BackupStore.readText(ctx, uri) }
            if (text == null) message = unreadableMsg else openText(text, null)
        }
    }

    Scaffold(topBar = { BackTopBar(stringResource(R.string.bk_title), onBack) }) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Hero(Icons.Rounded.Backup, stringResource(R.string.bk_hero_title), stringResource(R.string.bk_hero_sub))

            Text(
                stringResource(R.string.bk_pick_title), style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(start = 6.dp, top = 4.dp)
            )
            BackupPart.values().forEach { part ->
                val n = counts?.get(part)
                PartTile(
                    part = part, count = n, checked = part in chosen, enabled = n != 0,
                    onToggle = { chosen = if (part in chosen) chosen - part else chosen + part }
                )
            }

            // ---- password
            Surface(shape = RoundedCornerShape(28.dp), color = MaterialTheme.colorScheme.surfaceContainer, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(horizontal = 18.dp, vertical = 14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Rounded.Lock, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(stringResource(R.string.bk_pw_switch), style = MaterialTheme.typography.bodyLarge)
                            Text(
                                stringResource(R.string.bk_pw_sub), style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(checked = passwordOn, enabled = BackupPart.SECRETS !in chosen, onCheckedChange = { usePassword = it })
                    }
                    AnimatedVisibility(passwordOn) {
                        Column {
                            Spacer(Modifier.height(10.dp))
                            OutlinedTextField(
                                value = password, onValueChange = { password = it.take(128) },
                                label = { Text(stringResource(R.string.bk_pw_field)) },
                                singleLine = true,
                                visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                                trailingIcon = {
                                    IconButton(onClick = { showPassword = !showPassword }) {
                                        Icon(
                                            if (showPassword) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility,
                                            contentDescription = stringResource(if (showPassword) R.string.bk_hide else R.string.bk_show)
                                        )
                                    }
                                },
                                shape = RoundedCornerShape(18.dp),
                                modifier = Modifier.fillMaxWidth()
                            )
                            HelperText(stringResource(R.string.bk_pw_hint_min))
                            if (BackupPart.SECRETS in chosen) HelperText(stringResource(R.string.bk_pw_required))
                        }
                    }
                }
            }

            Button(
                onClick = { create.launch("madshield-backup-${java.time.LocalDate.now()}.json") },
                enabled = canCreate,
                shape = RoundedCornerShape(28.dp),
                modifier = Modifier.fillMaxWidth().height(56.dp)
            ) {
                Icon(Icons.Rounded.Backup, null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(if (busy) R.string.bk_creating else R.string.bk_create))
            }

            message?.let { InfoHint(it) }

            // ---- restore
            Surface(shape = RoundedCornerShape(36.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(horizontal = 20.dp, vertical = 18.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier.size(44.dp).clip(CircleShape).background(MaterialTheme.colorScheme.tertiaryContainer),
                            contentAlignment = Alignment.Center
                        ) { Icon(Icons.Rounded.Restore, null, tint = MaterialTheme.colorScheme.onTertiaryContainer) }
                        Spacer(Modifier.width(14.dp))
                        Column {
                            Text(stringResource(R.string.bk_restore_title), style = MaterialTheme.typography.titleMedium)
                            Text(
                                stringResource(R.string.bk_restore_sub), style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    Spacer(Modifier.height(14.dp))
                    FilledTonalButton(
                        onClick = { open.launch(arrayOf("*/*")) },
                        shape = RoundedCornerShape(24.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(stringResource(R.string.bk_restore_pick)) }
                }
            }

            HelperText(stringResource(R.string.bk_foot))
            Spacer(Modifier.height(24.dp))
        }
    }

    // ---- password of a protected backup
    waitingText?.let { text ->
        var input by remember(text) { mutableStateOf("") }
        var checking by remember(text) { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { waitingText = null; wrongPassword = false },
            title = { Text(stringResource(R.string.bk_need_pw)) },
            text = {
                Column {
                    Text(stringResource(R.string.bk_need_pw_body), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = input, onValueChange = { input = it.take(128); wrongPassword = false },
                        singleLine = true, isError = wrongPassword,
                        label = { Text(stringResource(R.string.bk_pw_field)) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        shape = RoundedCornerShape(18.dp)
                    )
                    if (wrongPassword) HelperText(stringResource(R.string.bk_wrong_pw), error = true)
                }
            },
            confirmButton = {
                TextButton(enabled = input.isNotEmpty() && !checking, onClick = {
                    scope.launch { checking = true; openText(text, input); checking = false }
                }) { Text(stringResource(R.string.bk_open)) }
            },
            dismissButton = {
                TextButton(onClick = { waitingText = null; wrongPassword = false }) { Text(stringResource(R.string.action_cancel)) }
            }
        )
    }

    // ---- what to bring back
    found?.let { doc ->
        val contents = remember(doc) { BackupStore.contents(doc) }
        RestoreSheet(
            doc = doc, contents = contents, idle = idle,
            onDismiss = { found = null },
            onRestore = { parts ->
                found = null
                scope.launch {
                    busy = true
                    val report = withContext(Dispatchers.IO) { BackupStore.restore(ctx, store, doc, parts, allowUsage = idle) }
                    counts = withContext(Dispatchers.IO) { BackupStore.summarize(ctx, store) }
                    busy = false
                    val done = report.applied.filter { it.value > 0 }
                    val labels = done.entries.joinToString(" · ") { (p, n) -> "${ctx.getString(partTitle(p))} ${partCountText(ctx, p, n)}" }
                    message = buildString {
                        append(if (done.isEmpty()) ctx.getString(R.string.bk_restored_none) else ctx.getString(R.string.bk_restored, labels))
                        if (report.usageSkipped) append("\n").append(ctx.getString(R.string.bk_usage_skipped))
                        if (report.secretsFailed) append("\n").append(ctx.getString(R.string.bk_secrets_failed))
                    }
                }
            }
        )
    }
}

// ------------------------------------------------------------------------------------------------ pieces

@Composable
private fun Hero(icon: ImageVector, title: String, sub: String) {
    val cs = MaterialTheme.colorScheme
    Surface(shape = RoundedCornerShape(36.dp), color = cs.primaryContainer, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(horizontal = 20.dp, vertical = 20.dp), verticalAlignment = Alignment.CenterVertically) {
            CookieBadge(68.dp) { Icon(icon, null, tint = cs.onPrimaryContainer, modifier = Modifier.size(30.dp)) }
            Spacer(Modifier.width(16.dp))
            Column {
                Text(title, style = MaterialTheme.typography.titleLarge, color = cs.onPrimaryContainer)
                Spacer(Modifier.height(2.dp))
                Text(sub, style = MaterialTheme.typography.bodySmall, color = cs.onPrimaryContainer.copy(alpha = 0.78f))
            }
        }
    }
}

private fun partIcon(p: BackupPart): ImageVector = when (p) {
    BackupPart.SETTINGS -> Icons.Rounded.Tune
    BackupPart.ROUTING -> Icons.Rounded.Security
    BackupPart.APPEARANCE -> Icons.Rounded.Palette
    BackupPart.USAGE -> Icons.Rounded.DataUsage
    BackupPart.SECRETS -> Icons.Rounded.Lock
}

private fun partTitle(p: BackupPart): Int = when (p) {
    BackupPart.SETTINGS -> R.string.bk_part_settings
    BackupPart.ROUTING -> R.string.bk_part_routing
    BackupPart.APPEARANCE -> R.string.bk_part_appearance
    BackupPart.USAGE -> R.string.bk_part_usage
    BackupPart.SECRETS -> R.string.bk_part_secrets
}

private fun partSub(p: BackupPart): Int = when (p) {
    BackupPart.SETTINGS -> R.string.bk_part_settings_sub
    BackupPart.ROUTING -> R.string.bk_part_routing_sub
    BackupPart.APPEARANCE -> R.string.bk_part_appearance_sub
    BackupPart.USAGE -> R.string.bk_part_usage_sub
    BackupPart.SECRETS -> R.string.bk_part_secrets_sub
}

private fun partCountText(ctx: android.content.Context, p: BackupPart, n: Int): String =
    ctx.getString(if (p == BackupPart.USAGE) R.string.bk_days else R.string.bk_items, n)

/** One selectable part: its icon, name, what it holds, how much of it there is, and a check box. */
@Composable
private fun PartTile(
    part: BackupPart, count: Int?, checked: Boolean, enabled: Boolean, onToggle: () -> Unit, note: String? = null
) {
    val cs = MaterialTheme.colorScheme
    val bg by animateColorAsState(if (checked && enabled) cs.primaryContainer else cs.surfaceContainerHigh, label = "bk-tile-bg")
    val badge by animateColorAsState(if (checked && enabled) cs.primary else cs.surfaceContainerHighest, label = "bk-tile-badge")
    val badgeInk = if (checked && enabled) cs.onPrimary else cs.onSurfaceVariant
    val ctx = LocalContext.current
    Surface(onClick = onToggle, enabled = enabled, shape = RoundedCornerShape(28.dp), color = bg, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(44.dp).clip(CircleShape).background(badge), contentAlignment = Alignment.Center) {
                Icon(partIcon(part), null, tint = badgeInk, modifier = Modifier.size(22.dp))
            }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(partTitle(part)), style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (part.sensitive) {
                        Spacer(Modifier.width(8.dp))
                        Surface(shape = CircleShape, color = cs.tertiaryContainer) {
                            Text(
                                stringResource(R.string.bk_sensitive), Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall, color = cs.onTertiaryContainer, maxLines = 1
                            )
                        }
                    }
                }
                Text(stringResource(partSub(part)), style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
                val line = note ?: when {
                    count == null -> null
                    count == 0 -> stringResource(R.string.bk_empty)
                    else -> partCountText(ctx, part, count)
                }
                if (line != null) Text(line, style = MaterialTheme.typography.labelMedium, color = cs.onSurfaceVariant)
            }
            Checkbox(checked = checked && enabled, onCheckedChange = null, enabled = enabled)
        }
    }
}

/** What the picked file holds, each part with a check box; only the ticked ones are brought back. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RestoreSheet(
    doc: BackupDoc, contents: Map<BackupPart, Int>, idle: Boolean,
    onDismiss: () -> Unit, onRestore: (Set<BackupPart>) -> Unit
) {
    val ctx = LocalContext.current
    var pick by remember(doc) { mutableStateOf(contents.filter { it.value > 0 && (idle || it.key != BackupPart.USAGE) }.keys.toSet()) }
    val made = if (doc.createdMs > 0) DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.getDefault()).format(Date(doc.createdMs)) else null
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(stringResource(R.string.bk_found_title), style = MaterialTheme.typography.titleLarge)
            if (made != null) {
                Text(
                    if (doc.appVersion.isNotEmpty()) stringResource(R.string.bk_found_sub, made, doc.appVersion) else stringResource(R.string.bk_found_sub_nover, made),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            contents.forEach { (part, n) ->
                val blocked = part == BackupPart.USAGE && !idle
                PartTile(
                    part = part, count = n, checked = part in pick, enabled = n > 0 && !blocked,
                    onToggle = { pick = if (part in pick) pick - part else pick + part },
                    note = when {
                        blocked -> stringResource(R.string.bk_note_usage_busy)
                        n == 0 -> null
                        else -> partCountText(ctx, part, n) + " · " + stringResource(
                            when (part) {
                                BackupPart.USAGE -> R.string.bk_note_usage
                                BackupPart.SECRETS -> R.string.bk_note_secrets
                                else -> R.string.bk_note_settings
                            }
                        )
                    }
                )
            }
            Button(
                onClick = { onRestore(pick) }, enabled = pick.isNotEmpty(),
                shape = RoundedCornerShape(28.dp), modifier = Modifier.fillMaxWidth().height(52.dp)
            ) { Text(stringResource(R.string.bk_do_restore)) }
        }
    }
}
