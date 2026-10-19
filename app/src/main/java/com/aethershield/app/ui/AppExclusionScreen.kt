package com.aethershield.app.ui

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.*
import com.aethershield.app.ui.components.BackTopBar
import com.aethershield.app.ui.components.HelperText
import com.aethershield.app.ui.components.SegmentedChoice
import com.aethershield.app.ui.components.SwitchRow

private data class AppEntry(val packageName: String, val label: String, val isSystem: Boolean)

@Composable
fun AppExclusionScreen(
    packageManager: PackageManager,
    selfPackage: String,
    config: EngineConfig,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit,
    onBack: () -> Unit
) {
    var showSystem by remember { mutableStateOf(false) }

    // Apps with a launcher icon are always listed. "Show system apps" adds every other installed package
    // (system services, Google Play services...), which is where background traffic often comes from.
    val apps = remember(showSystem) {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val launcher = packageManager.queryIntentActivities(launcherIntent, 0).map { it.activityInfo.packageName }
        val pkgs = if (showSystem) {
            (launcher + runCatching { packageManager.getInstalledApplications(0).map { it.packageName } }.getOrDefault(emptyList()))
        } else launcher
        pkgs.distinct()
            .filter { it != selfPackage }
            .mapNotNull { pkg ->
                runCatching {
                    val ai = packageManager.getApplicationInfo(pkg, 0)
                    AppEntry(
                        pkg,
                        packageManager.getApplicationLabel(ai).toString(),
                        (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    )
                }.getOrNull()
            }
            .sortedBy { it.label.lowercase() }
    }

    var mode by remember(config.appSelectionMode) { mutableStateOf(config.appSelectionMode) }
    var selected by remember(config.selectedPackages) { mutableStateOf(config.selectedPackages) }
    var query by remember { mutableStateOf("") }
    val shown = remember(apps, query) {
        if (query.isBlank()) apps
        else apps.filter { it.label.contains(query.trim(), ignoreCase = true) || it.packageName.contains(query.trim(), ignoreCase = true) }
    }

    // What the RUNNING VPN interface was built with (null when none): the only thing that can be called verified.
    val active by AetherController.active.collectAsState()
    val applied = active?.let { AppRouting(it.appSelectionMode, it.selectedPackages) }
    val draft = AppRouting(mode, selected)

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
            HelperText(stringResource(R.string.apps_status_note))
            SwitchRow(stringResource(R.string.apps_show_system), stringResource(R.string.apps_show_system_sub), showSystem, { showSystem = it })
            Spacer(Modifier.height(4.dp))

            OutlinedTextField(
                value = query, onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(), singleLine = true,
                label = { Text(stringResource(R.string.apps_search)) }
            )
            Spacer(Modifier.height(4.dp))
            LazyColumn(Modifier.weight(1f)) {
                items(shown, key = { it.packageName }) { app ->
                    val view = SplitTunnel.view(app.packageName, selfPackage, draft, config.mode, applied)
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        if (mode != AppSelectionMode.NONE) {
                            Checkbox(
                                checked = app.packageName in selected,
                                onCheckedChange = { checked ->
                                    selected = if (checked) selected + app.packageName else selected - app.packageName
                                }
                            )
                        } else {
                            Spacer(Modifier.width(12.dp))
                        }
                        Column(Modifier.weight(1f)) {
                            Text(
                                if (app.isSystem) "${app.label}  ·  ${stringResource(R.string.apps_system_badge)}" else app.label,
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                routeText(view),
                                style = MaterialTheme.typography.bodySmall,
                                color = routeColor(view.status)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun plannedWord(s: RouteStatus): String =
    stringResource(if (s == RouteStatus.VIA_VPN) R.string.app_planned_via else R.string.app_planned_direct)

@Composable
private fun routeText(v: RouteView): String = when (v.reason) {
    RouteReason.THIS_APP -> stringResource(R.string.app_route_this_app)
    RouteReason.PROXY_MODE -> stringResource(R.string.app_route_unverified_proxy)
    RouteReason.NOT_CONNECTED -> stringResource(R.string.app_route_unverified_disconnected, plannedWord(v.planned))
    RouteReason.PENDING_RECONNECT -> stringResource(R.string.app_route_unverified_pending, plannedWord(v.planned))
    RouteReason.NONE -> stringResource(if (v.status == RouteStatus.VIA_VPN) R.string.app_route_via else R.string.app_route_direct)
}

@Composable
private fun routeColor(s: RouteStatus): Color = when (s) {
    RouteStatus.VIA_VPN -> MaterialTheme.colorScheme.primary
    RouteStatus.DIRECT -> MaterialTheme.colorScheme.onSurfaceVariant
    RouteStatus.UNVERIFIABLE -> MaterialTheme.colorScheme.tertiary
}
