package com.aethershield.app.ui

import android.content.Intent
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.AppSelectionMode
import com.aethershield.app.core.EngineConfig
import com.aethershield.app.ui.components.BackTopBar
import com.aethershield.app.ui.components.HelperText
import com.aethershield.app.ui.components.SegmentedChoice

private data class AppEntry(val packageName: String, val label: String)

@Composable
fun AppExclusionScreen(
    packageManager: PackageManager,
    selfPackage: String,
    config: EngineConfig,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit,
    onBack: () -> Unit
) {
    val apps = remember {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        packageManager.queryIntentActivities(launcherIntent, 0)
            .map { it.activityInfo.packageName }
            .distinct()
            .filter { it != selfPackage }
            .mapNotNull { pkg ->
                runCatching {
                    val ai = packageManager.getApplicationInfo(pkg, 0)
                    AppEntry(pkg, packageManager.getApplicationLabel(ai).toString())
                }.getOrNull()
            }
            .sortedBy { it.label.lowercase() }
    }

    var mode by remember(config.appSelectionMode) { mutableStateOf(config.appSelectionMode) }
    var selected by remember(config.selectedPackages) { mutableStateOf(config.selectedPackages) }
    var query by remember { mutableStateOf("") }
    val shown = remember(apps, query) {
        if (query.isBlank()) apps else apps.filter { it.label.contains(query.trim(), ignoreCase = true) }
    }

    Scaffold(topBar = {
        BackTopBar(stringResource(R.string.apps_title), onBack, actions = {
            TextButton(onClick = {
                onUpdate { it.copy(appSelectionMode = mode, selectedPackages = selected) }
                onBack()
            }) { Text(stringResource(R.string.action_save)) }
        })
    }) { padding ->
        Column(Modifier.padding(padding).padding(horizontal = 16.dp)) {
            SegmentedChoice(
                options = listOf(
                    stringResource(R.string.apps_mode_none) to AppSelectionMode.NONE,
                    stringResource(R.string.apps_mode_exclude) to AppSelectionMode.EXCLUDE_SELECTED,
                    stringResource(R.string.apps_mode_include) to AppSelectionMode.INCLUDE_ONLY_SELECTED
                ),
                selected = mode,
                onSelect = { mode = it }
            )
            HelperText(stringResource(R.string.apps_vpn_only))
            Spacer(Modifier.height(8.dp))

            if (mode != AppSelectionMode.NONE) {
                OutlinedTextField(
                    value = query, onValueChange = { query = it },
                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                    label = { Text(stringResource(R.string.apps_search)) }
                )
                Spacer(Modifier.height(4.dp))
                LazyColumn(Modifier.weight(1f)) {
                    items(shown, key = { it.packageName }) { app ->
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = app.packageName in selected,
                                onCheckedChange = { checked ->
                                    selected = if (checked) selected + app.packageName else selected - app.packageName
                                }
                            )
                            Text(app.label, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            } else {
                Spacer(Modifier.height(24.dp))
                Text(stringResource(R.string.apps_all_tunneled), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
