package com.aethershield.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.*
import com.aethershield.app.ui.components.*
import com.aethershield.app.ui.theme.DarkMode
import com.aethershield.app.ui.theme.Palettes
import com.aethershield.app.ui.theme.UiPrefs
import kotlin.math.roundToInt
import android.widget.Toast

@Composable
fun SettingsScreen(
    config: EngineConfig,
    uiPrefs: UiPrefs,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit,
    onUpdateUi: ((UiPrefs) -> UiPrefs) -> Unit,
    onOpenDiagnostics: () -> Unit,
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
        PageHeader(stringResource(R.string.nav_settings), stringResource(R.string.settings_apply_next))

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

        // ---------------------------------------------------------------- chain
        SectionCard(stringResource(R.string.sec_chain)) {
            if (config.protocol == Protocol.SMART) {
                HelperText(stringResource(R.string.chain_needs_protocol))
            } else {
                ChoiceChips(
                    listOf(
                        stringResource(R.string.chain_none) to PrivacyChain.NONE,
                        stringResource(R.string.chain_psiphon) to PrivacyChain.PSIPHON,
                        stringResource(R.string.chain_tor) to PrivacyChain.TOR
                    ),
                    config.privacyChain,
                    onSelect = { v -> onUpdate { it.copy(privacyChain = v) } }
                )
                when (config.privacyChain) {
                    PrivacyChain.NONE -> HelperText(stringResource(R.string.chain_help))
                    PrivacyChain.PSIPHON -> {
                        SubLabel(stringResource(R.string.lbl_psiphon_region))
                        ChoiceChips(
                            listOf(stringResource(R.string.region_auto) to (null as String?)) +
                                Chain.REGIONS.map { regionLabel(it) to (it as String?) },
                            Chain.normalizeRegion(config.psiphonRegion),
                            onSelect = { v -> onUpdate { it.copy(psiphonRegion = v) } }
                        )
                        HelperText(stringResource(R.string.chain_psiphon_help))
                    }
                    PrivacyChain.TOR -> HelperText(stringResource(R.string.chain_tor_help))
                }
            }
        }

        // ---------------------------------------------------------------- tuning
        SectionCard(stringResource(R.string.sec_engine)) {
            SubLabel(stringResource(R.string.lbl_scan))
            ChoiceChips(
                CoreChoices.SCAN_MODES.map { scanLabel(it) to it }, config.scanMode,
                onSelect = { v -> onUpdate { it.copy(scanMode = v) } }
            )
            HelperText(stringResource(R.string.scan_help))

            SubLabel(stringResource(R.string.lbl_perf))
            ChoiceChips(
                listOf(
                    stringResource(R.string.perf_auto) to "auto",
                    stringResource(R.string.perf_medium) to "medium",
                    stringResource(R.string.perf_low) to "low"
                ),
                CoreChoices.perfOrDefault(config.perfProfile),
                onSelect = { v -> onUpdate { it.copy(perfProfile = v) } }
            )
            HelperText(stringResource(R.string.perf_help))

            SubLabel(stringResource(R.string.lbl_ip))
            ChoiceChips(
                CoreChoices.IP_MODES.map { ipLabel(it) to it }, config.ipMode,
                onSelect = { v -> onUpdate { it.copy(ipMode = v) } }
            )

            SubLabel(stringResource(R.string.lbl_noize))
            ChoiceChips(
                CoreChoices.NOIZE_PROFILES.map { noizeLabel(it) to it }, config.noizeProfile,
                onSelect = { v -> onUpdate { it.copy(noizeProfile = v) } }
            )
            HelperText(stringResource(R.string.noize_help))

            Spacer(Modifier.height(8.dp))
            SwitchRow(
                stringResource(R.string.sw_fragment), stringResource(R.string.sw_fragment_sub),
                config.fragment, { v -> onUpdate { it.copy(fragment = v) } }
            )
            SwitchRow(
                stringResource(R.string.sw_ech), stringResource(R.string.sw_ech_sub),
                config.ech, { v -> onUpdate { it.copy(ech = v) } }
            )
            SwitchRow(
                stringResource(R.string.sw_quick), stringResource(R.string.sw_quick_sub),
                config.quickReconnect, { v -> onUpdate { it.copy(quickReconnect = v) } }
            )

            SubLabel(stringResource(R.string.lbl_mtu, config.mtu))
            var mtu by remember(config.mtu) { mutableFloatStateOf(config.mtu.toFloat()) }
            Slider(
                value = mtu,
                onValueChange = { mtu = it },
                onValueChangeFinished = {
                    val snapped = ((mtu / 10f).roundToInt() * 10).coerceIn(CoreChoices.MIN_MTU, CoreChoices.MAX_MTU)
                    onUpdate { it.copy(mtu = snapped) }
                },
                valueRange = CoreChoices.MIN_MTU.toFloat()..CoreChoices.MAX_MTU.toFloat(),
                steps = (CoreChoices.MAX_MTU - CoreChoices.MIN_MTU) / 10 - 1
            )
            HelperText(stringResource(R.string.mtu_help))
            if (config.effectiveMtu != config.mtu) {
                HelperText(stringResource(R.string.mtu_capped, config.effectiveMtu))
            }
        }

        // ---------------------------------------------------------------- protection
        SectionCard(stringResource(R.string.sec_protection)) {
            SwitchRow(
                stringResource(R.string.sw_exit_guard), stringResource(R.string.sw_exit_guard_sub),
                config.exitLoc?.contains("!IR") == true,
                { v -> onUpdate { it.copy(exitLoc = if (v) "!IR" else null) } }
            )
            val ctx = LocalContext.current
            TextButton(onClick = {
                val n = IdentityReset.reset(ctx.filesDir)
                Toast.makeText(
                    ctx,
                    if (n > 0) ctx.getString(R.string.identity_reset_done, n) else ctx.getString(R.string.identity_reset_none),
                    Toast.LENGTH_LONG
                ).show()
            }) { Text(stringResource(R.string.action_reset_identity)) }
            HelperText(stringResource(R.string.identity_reset_help))
            SwitchRow(
                stringResource(R.string.sw_kill), stringResource(R.string.sw_kill_sub),
                config.killSwitchEnabled, { v -> onUpdate { it.copy(killSwitchEnabled = v) } }
            )
            Spacer(Modifier.height(8.dp))
            var team by remember(config.zeroTrustTeam) { mutableStateOf(config.zeroTrustTeam ?: "") }
            OutlinedTextField(
                value = team, onValueChange = { team = it },
                label = { Text(stringResource(R.string.lbl_zt_team)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                trailingIcon = {
                    TextButton(
                        onClick = { onUpdate { it.copy(zeroTrustTeam = team.trim().ifBlank { null }) } },
                        enabled = team.trim() != (config.zeroTrustTeam ?: "")
                    ) { Text(stringResource(R.string.action_save)) }
                }
            )
            HelperText(stringResource(R.string.zt_help))
        }

        // ---------------------------------------------------------------- appearance
        SectionCard(stringResource(R.string.sec_appearance)) {
            SubLabel(stringResource(R.string.lbl_palette))
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Palettes.ALL.forEach { p ->
                    val on = p.id == uiPrefs.themeId
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.clip(MaterialTheme.shapes.medium)
                            .clickable { onUpdateUi { it.copy(themeId = p.id) } }
                            .padding(4.dp)
                    ) {
                        Box(
                            Modifier.size(46.dp).clip(CircleShape)
                                .background(Brush.linearGradient(listOf(p.primary, p.tertiary))),
                            contentAlignment = Alignment.Center
                        ) {
                            if (on) Icon(Icons.Rounded.Check, null, tint = androidx.compose.ui.graphics.Color.White)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(
                            p.name, style = MaterialTheme.typography.labelSmall,
                            color = if (on) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            SubLabel(stringResource(R.string.lbl_dark_mode))
            ChoiceChips(
                listOf(
                    stringResource(R.string.dark_system) to DarkMode.SYSTEM,
                    stringResource(R.string.dark_light) to DarkMode.LIGHT,
                    stringResource(R.string.dark_dark) to DarkMode.DARK
                ),
                uiPrefs.darkMode, { v -> onUpdateUi { it.copy(darkMode = v) } }
            )
            SwitchRow(
                stringResource(R.string.sw_amoled), stringResource(R.string.sw_amoled_sub),
                uiPrefs.amoled, { v -> onUpdateUi { it.copy(amoled = v) } }
            )
        }

        // ---------------------------------------------------------------- privacy
        NavRow(
            Icons.Rounded.Speed,
            stringResource(R.string.diag_title),
            stringResource(R.string.diag_nav_sub),
            onOpenDiagnostics
        )
        SectionCard(stringResource(R.string.sec_privacy)) {
            Text(
                stringResource(R.string.privacy_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(NavClearance))
    }
}

@Composable
private fun SubLabel(text: String) {
    Text(
        text, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurface,
        modifier = Modifier.padding(top = 12.dp, bottom = 6.dp)
    )
}

/** "DE" -> flag emoji + code, so the chips are recognisable at a glance. */
private fun regionLabel(code: String): String {
    val flag = String(code.map { Character.toChars(0x1F1E6 + (it - 'A')) }.flatMap { it.asList() }.toCharArray())
    return "$flag $code"
}
