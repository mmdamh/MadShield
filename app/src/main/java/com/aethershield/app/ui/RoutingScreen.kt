package com.aethershield.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
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

@Composable
fun RoutingScreen(
    config: EngineConfig,
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
        Spacer(Modifier.height(NavClearance))
    }
}
