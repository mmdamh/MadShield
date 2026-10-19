package com.aethershield.app.ui

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.AppSelectionMode
import com.aethershield.app.core.ConnectionMode
import com.aethershield.app.core.EngineConfig
import com.aethershield.app.ui.components.HelperText
import com.aethershield.app.ui.components.NavClearance
import com.aethershield.app.ui.components.NavRow
import com.aethershield.app.ui.components.PageHeader
import com.aethershield.app.ui.components.SectionCard
import com.aethershield.app.ui.components.SwitchRow

@Composable
fun RoutingScreen(
    config: EngineConfig,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit,
    onOpenBypass: () -> Unit,
    onOpenApps: () -> Unit,
    contentPadding: PaddingValues
) {
    Column(
        Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        PageHeader(stringResource(R.string.nav_routing), stringResource(R.string.routing_subtitle))
        NavRow(
            Icons.Rounded.Language,
            stringResource(R.string.routing_rules_title),
            stringResource(R.string.routing_rules_sub, config.directRules.size, config.blockRules.size),
            onOpenBypass
        )
        NavRow(
            Icons.Rounded.Apps,
            stringResource(R.string.routing_apps_title),
            when (config.appSelectionMode) {
                AppSelectionMode.NONE -> stringResource(R.string.routing_apps_none)
                AppSelectionMode.EXCLUDE_SELECTED ->
                    stringResource(R.string.routing_apps_exclude, config.selectedPackages.size)
                AppSelectionMode.INCLUDE_ONLY_SELECTED ->
                    stringResource(R.string.routing_apps_include, config.selectedPackages.size)
            },
            onOpenApps
        )
        if (config.mode == ConnectionMode.PROXY_ONLY) {
            HelperText(stringResource(R.string.routing_proxy_note))
        }
        val ctx = LocalContext.current
        SectionCard(stringResource(R.string.sec_leak)) {
            SwitchRow(
                stringResource(R.string.sw_kill), stringResource(R.string.sw_kill_sub),
                config.killSwitchEnabled, { v -> onUpdate { it.copy(killSwitchEnabled = v) } }
            )
            HelperText(stringResource(R.string.leak_limits))
            TextButton(onClick = {
                runCatching {
                    ctx.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                }
            }) { Text(stringResource(R.string.action_open_vpn_settings)) }
            HelperText(stringResource(R.string.leak_system_lockdown))
        }
        Spacer(Modifier.height(NavClearance))
    }
}
