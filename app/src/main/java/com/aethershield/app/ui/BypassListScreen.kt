package com.aethershield.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.UploadFile
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.AetherController
import com.aethershield.app.core.ConnectionState
import com.aethershield.app.core.EngineConfig
import com.aethershield.app.core.RuleLists
import com.aethershield.app.core.RuleParser
import com.aethershield.app.core.RuleSource
import com.aethershield.app.core.RuleTarget
import com.aethershield.app.ui.components.BackTopBar
import com.aethershield.app.ui.components.HelperText
import com.aethershield.app.ui.components.MonoFamily
import java.text.DateFormat
import java.util.Date

/**
 * "Direct" = bypass the tunnel entirely (domestic sites that reject foreign IPs, banks, ...).
 * "Block" = refuse the connection outright (ad and tracker lists).
 *
 * Two kinds of rules live here:
 *  - typed rules, in the text box (small; kept in settings);
 *  - imported lists (a file, or a link to a hosts / AdGuard / domain list), which can be huge. Those are
 *    cleaned and stored as files by [RuleLists], never put in the text box.
 * The rule grammar belongs to the engine (example.com, full:, keyword:, regexp:, CIDR, port:, "private").
 */
@Composable
fun BypassListScreen(config: EngineConfig, onUpdate: ((EngineConfig) -> EngineConfig) -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    val lists = remember { RuleLists.get(context) }
    val sources by lists.sources.collectAsState()
    val status by lists.status.collectAsState()

    var tab by remember { mutableIntStateOf(0) }
    var directText by remember(config.directRules) { mutableStateOf(config.directRules.joinToString("\n")) }
    var blockText by remember(config.blockRules) { mutableStateOf(config.blockRules.joinToString("\n")) }
    var url by remember { mutableStateOf("") }
    val mono = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFamily, textDirection = TextDirection.Ltr)
    val target = if (tab == 0) RuleTarget.DIRECT else RuleTarget.BLOCK

    // Any file type: hosts files and list dumps often have no "text/plain" type and would be greyed out.
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) lists.importFile(uri, if (tab == 0) RuleTarget.DIRECT else RuleTarget.BLOCK)
    }

    /** Through the tunnel when it is up (list hosts are often unreachable from a filtered network). */
    fun tunnelPort(): Int? = if (AetherController.state.value is ConnectionState.Connected) config.socksPort else null

    DisposableEffect(Unit) { onDispose { lists.clearMessage() } }

    Scaffold(topBar = { BackTopBar(stringResource(R.string.rules_title), onBack) }) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)
        ) {
            TabRow(selectedTabIndex = tab, containerColor = MaterialTheme.colorScheme.surface) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text(stringResource(R.string.rules_direct)) })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text(stringResource(R.string.rules_block)) })
            }
            Spacer(Modifier.height(12.dp))
            HelperText(stringResource(if (tab == 0) R.string.rules_direct_help else R.string.rules_block_help))
            Spacer(Modifier.height(12.dp))

            // ---- imported lists
            Text(stringResource(R.string.rules_sources_title), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            val mine = sources.filter { it.target == target }
            if (mine.isEmpty()) {
                HelperText(stringResource(R.string.rules_sources_empty))
            } else {
                mine.forEach { src ->
                    SourceRow(
                        src = src,
                        busy = status.busy,
                        onToggle = { lists.setEnabled(src.id, it) },
                        onRefresh = if (src.url != null) ({ lists.refresh(src.id, tunnelPort()) }) else null,
                        onDelete = { lists.remove(src.id) }
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { picker.launch(arrayOf("*/*")) },
                enabled = !status.busy,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Rounded.UploadFile, null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.rules_import))
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = url, onValueChange = { url = it },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    textStyle = mono,
                    placeholder = { Text("https://…", style = mono) }
                )
                Spacer(Modifier.width(8.dp))
                FilledTonalIconButton(
                    onClick = { lists.addUrl(url, target, tunnelPort()); url = "" },
                    enabled = url.isNotBlank() && !status.busy
                ) { Icon(Icons.Rounded.Add, stringResource(R.string.rules_url_add)) }
            }
            HelperText(stringResource(R.string.rules_url_help))
            if (tab == 1) {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { url = PRESET_STEVENBLACK }) { Text("StevenBlack hosts") }
                    TextButton(onClick = { url = PRESET_ADGUARD }) { Text("AdGuard DNS filter") }
                }
            }
            if (status.busy) {
                Spacer(Modifier.height(6.dp))
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            status.message?.let { HelperText(it, error = status.error) }
            HelperText(stringResource(R.string.rules_size_note))

            // ---- typed rules
            Spacer(Modifier.height(20.dp))
            Text(stringResource(R.string.rules_manual_title), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(8.dp))
            if (tab == 0) {
                OutlinedTextField(
                    value = directText, onValueChange = { directText = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 160.dp),
                    textStyle = mono,
                    placeholder = { Text("example.ir\nfull:bank.example.ir\nkeyword:sheba\n10.0.0.0/8", style = mono) }
                )
            } else {
                OutlinedTextField(
                    value = blockText, onValueChange = { blockText = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 160.dp),
                    textStyle = mono,
                    placeholder = { Text("ads.example.com\nkeyword:tracker", style = mono) }
                )
            }
            Spacer(Modifier.height(12.dp))
            // One Save for both boxes: saving from one tab used to throw away unsaved edits in the other.
            Button(
                onClick = {
                    val d = RuleParser.normalizeManual(directText)
                    val b = RuleParser.normalizeManual(blockText)
                    onUpdate { it.copy(directRules = d, blockRules = b) }
                    onBack()
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text(stringResource(R.string.action_save)) }
            Spacer(Modifier.height(24.dp))
        }
    }
}

private const val PRESET_STEVENBLACK = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
private const val PRESET_ADGUARD = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"

@Composable
private fun SourceRow(
    src: RuleSource,
    busy: Boolean,
    onToggle: (Boolean) -> Unit,
    onRefresh: (() -> Unit)?,
    onDelete: () -> Unit
) {
    val date = remember(src.updatedAt) { DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(src.updatedAt)) }
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(
                src.name, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                stringResource(R.string.rules_source_sub, src.count, date),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (src.dropped > 0) HelperText(stringResource(R.string.rules_source_dropped, src.dropped), error = true)
        }
        if (onRefresh != null) {
            IconButton(onClick = onRefresh, enabled = !busy) {
                Icon(Icons.Rounded.Refresh, stringResource(R.string.rules_source_refresh))
            }
        }
        IconButton(onClick = onDelete) { Icon(Icons.Rounded.Delete, stringResource(R.string.rules_source_delete)) }
        Switch(checked = src.enabled, onCheckedChange = onToggle)
    }
}
