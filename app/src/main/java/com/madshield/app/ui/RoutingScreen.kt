package com.madshield.app.ui

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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.AppSelectionMode
import com.madshield.app.core.Protocol
import com.madshield.app.ui.components.SegmentedChoice
import com.madshield.app.core.ConnectionMode
import com.madshield.app.core.EngineConfig
import com.madshield.app.core.RuleLists
import com.madshield.app.core.RuleTarget
import com.madshield.app.ui.components.HelperText
import com.madshield.app.ui.components.NavClearance
import com.madshield.app.ui.components.NavRow
import com.madshield.app.ui.components.PageHeader
import com.madshield.app.ui.components.SectionCard
import com.madshield.app.ui.components.SwitchRow

@Composable
fun RoutingScreen(
    config: EngineConfig,
    connectionState: com.madshield.app.core.ConnectionState,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit,
    onOpenBypass: () -> Unit,
    onOpenApps: () -> Unit,
    contentPadding: PaddingValues
) {
    val ctx = LocalContext.current
    val sources by RuleLists.get(ctx).sources.collectAsState()
    val importedDirect = sources.filter { it.enabled && it.target == RuleTarget.DIRECT }.sumOf { it.count }
    val importedBlock = sources.filter { it.enabled && it.target == RuleTarget.BLOCK }.sumOf { it.count }
    Column(
        Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        PageHeader(stringResource(R.string.nav_routing), stringResource(R.string.routing_subtitle))
        // ---------------------------------------------------------------- protocol
        SectionCard(stringResource(R.string.sec_protocol)) {
            SegmentedChoice(
                options = Protocol.entries.map { protocolLong(it) to it },
                selected = config.protocol,
                onSelect = { p -> onUpdate { it.copy(protocol = p) } }
            )
            HelperText(stringResource(R.string.protocol_help))
            if (config.protocol == Protocol.GOOL) {
                SwitchRow(
                    stringResource(R.string.sw_gool_h2), stringResource(R.string.sw_gool_h2_sub),
                    config.masqueHttp2, { v -> onUpdate { it.copy(masqueHttp2 = v) } }
                )
            }
        }

        ProfileCard(config, connectionState, onUpdate)
        Text(
            stringResource(R.string.sec_traffic_control), style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp, start = 4.dp)
        )
        NavRow(
            Icons.Rounded.Language,
            stringResource(R.string.routing_rules_title),
            stringResource(R.string.routing_rules_sub, config.directRules.size + importedDirect, config.blockRules.size + importedBlock),
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
        Spacer(Modifier.height(NavClearance))
    }
}
