package com.aethershield.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.UploadFile
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.EngineConfig
import com.aethershield.app.ui.components.BackTopBar
import com.aethershield.app.ui.components.HelperText
import com.aethershield.app.ui.components.MonoFamily

/**
 * "Direct" = bypass the tunnel entirely (domestic sites that reject foreign IPs, banks, ...).
 * "Block" = refuse the connection outright. The rule grammar belongs to the engine
 * (example.com, full:, keyword:, regexp:, CIDR, port:, "private"); this app forwards it
 * unchanged and does not parse or validate it.
 */
@Composable
fun BypassListScreen(config: EngineConfig, onUpdate: ((EngineConfig) -> EngineConfig) -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    var tab by remember { mutableIntStateOf(0) }
    var directText by remember(config.directRules) { mutableStateOf(config.directRules.joinToString("\n")) }
    var blockText by remember(config.blockRules) { mutableStateOf(config.blockRules.joinToString("\n")) }
    val mono = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFamily, textDirection = TextDirection.Ltr)

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri ?: return@rememberLauncherForActivityResult
        runCatching {
            context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        }.getOrNull()?.let { imported ->
            directText = (directText.lines() + imported.lines()).map { it.trim() }
                .filter { it.isNotBlank() }.distinct().joinToString("\n")
        }
    }

    fun rules(t: String) = t.lines().map { it.trim() }.filter { it.isNotBlank() }

    Scaffold(topBar = { BackTopBar(stringResource(R.string.rules_title), onBack) }) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)
        ) {
            TabRow(selectedTabIndex = tab, containerColor = MaterialTheme.colorScheme.surface) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text(stringResource(R.string.rules_direct)) })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text(stringResource(R.string.rules_block)) })
            }
            Spacer(Modifier.height(12.dp))

            if (tab == 0) {
                HelperText(stringResource(R.string.rules_direct_help))
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = { importLauncher.launch("text/plain") }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Rounded.UploadFile, null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.rules_import))
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = directText, onValueChange = { directText = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 240.dp),
                    textStyle = mono,
                    placeholder = { Text("example.ir\nfull:bank.example.ir\nkeyword:sheba\n10.0.0.0/8", style = mono) }
                )
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick = { onUpdate { it.copy(directRules = rules(directText)) }; onBack() },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.action_save)) }
            } else {
                HelperText(stringResource(R.string.rules_block_help))
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = blockText, onValueChange = { blockText = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 240.dp),
                    textStyle = mono,
                    placeholder = { Text("ads.example.com\nkeyword:tracker", style = mono) }
                )
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick = { onUpdate { it.copy(blockRules = rules(blockText)) }; onBack() },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.action_save)) }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
