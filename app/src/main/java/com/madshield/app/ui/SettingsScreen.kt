package com.madshield.app.ui

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
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.core.graphics.ColorUtils
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.*
import com.madshield.app.ui.components.*
import com.madshield.app.ui.theme.ConnectStyle
import com.madshield.app.ui.theme.DarkMode
import com.madshield.app.ui.theme.Palettes
import com.madshield.app.ui.theme.UiPrefs
import com.madshield.app.vpn.SingBoxTunEngine
import kotlin.math.roundToInt
import android.content.Intent
import android.provider.Settings
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

        // ---------------------------------------------------------------- update19: TLS look and MASQUE server name
        // Folded and off by default: with the defaults nothing new is sent to the core.
        val sniKind = MasqueSni.kindOf(config.masqueSni)
        val presetLabel = stringResource(
            when (config.tlsPreset) {
                TlsPreset.DEFAULT -> R.string.tls_default
                TlsPreset.CHROME_PLUS -> R.string.tls_chrome_plus
                TlsPreset.FIREFOX -> R.string.tls_firefox
            }
        )
        FoldCard(
            title = stringResource(R.string.sec_tls),
            summary = if (sniKind == MasqueSni.Kind.DEFAULT) presetLabel
            else presetLabel + " · " + stringResource(R.string.tls_summary_sni, config.masqueSni),
            icon = Icons.Rounded.Tune
        ) {
            SubLabel(stringResource(R.string.lbl_tls_look))
            ChoiceChips(
                listOf(
                    stringResource(R.string.tls_default) to TlsPreset.DEFAULT,
                    stringResource(R.string.tls_chrome_plus) to TlsPreset.CHROME_PLUS,
                    stringResource(R.string.tls_firefox) to TlsPreset.FIREFOX
                ),
                config.tlsPreset,
                onSelect = { v -> onUpdate { it.copy(tlsPreset = v) } }
            )
            HelperText(
                stringResource(
                    when (config.tlsPreset) {
                        TlsPreset.DEFAULT -> R.string.tls_help_default
                        TlsPreset.CHROME_PLUS -> R.string.tls_help_chrome
                        TlsPreset.FIREFOX -> R.string.tls_help_firefox
                    }
                )
            )

            SubLabel(stringResource(R.string.lbl_sni))
            var customOpen by remember(config.masqueSni) { mutableStateOf(sniKind == MasqueSni.Kind.CUSTOM) }
            val shownKind = if (customOpen) MasqueSni.Kind.CUSTOM else sniKind
            ChoiceChips(
                listOf(
                    stringResource(R.string.sni_default) to MasqueSni.Kind.DEFAULT,
                    stringResource(R.string.sni_warp) to MasqueSni.Kind.WARP_CLIENT,
                    stringResource(R.string.sni_custom) to MasqueSni.Kind.CUSTOM
                ),
                shownKind,
                onSelect = { k ->
                    when (k) {
                        MasqueSni.Kind.DEFAULT -> { customOpen = false; onUpdate { it.copy(masqueSni = "") } }
                        MasqueSni.Kind.WARP_CLIENT -> { customOpen = false; onUpdate { it.copy(masqueSni = MasqueSni.WARP_CLIENT) } }
                        MasqueSni.Kind.CUSTOM -> { customOpen = true }
                    }
                }
            )
            if (shownKind == MasqueSni.Kind.CUSTOM) {
                var text by remember(config.masqueSni) {
                    mutableStateOf(if (sniKind == MasqueSni.Kind.CUSTOM) config.masqueSni else "")
                }
                val valid = MasqueSni.isValid(text)
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = text, onValueChange = { text = it },
                    label = { Text(stringResource(R.string.sni_custom_label)) },
                    singleLine = true,
                    isError = text.isNotBlank() && !valid,
                    modifier = Modifier.fillMaxWidth(),
                    trailingIcon = {
                        TextButton(
                            onClick = { onUpdate { it.copy(masqueSni = MasqueSni.normalize(text) ?: "") } },
                            enabled = valid && MasqueSni.normalize(text) != config.masqueSni
                        ) { Text(stringResource(R.string.action_save)) }
                    }
                )
                if (text.isNotBlank() && !valid) HelperText(stringResource(R.string.sni_invalid), error = true)
            }
            if (!MasqueSni.appliesTo(config.protocol)) HelperText(stringResource(R.string.sni_not_masque))
            InfoHint(stringResource(R.string.tls_info))
        }

        // ---------------------------------------------------------------- update24: tunnel engine (experimental)
        // Folded; hev (the engine of every earlier version) stays the default and is what runs unless this is changed.
        val tunCtx = LocalContext.current
        val singTunInBuild = remember { SingBoxTunEngine.isInBuild(tunCtx) }
        FoldCard(
            title = stringResource(R.string.sec_tunengine),
            summary = stringResource(if (config.tunEngine == TunEngineId.HEV) R.string.tunengine_hev else R.string.tunengine_singbox),
            icon = Icons.Rounded.Tune
        ) {
            SubLabel(stringResource(R.string.lbl_tunengine))
            ChoiceChips(
                listOf(
                    stringResource(R.string.tunengine_hev) to TunEngineId.HEV,
                    stringResource(R.string.tunengine_singbox) to TunEngineId.SINGBOX_TUN
                ),
                config.tunEngine,
                onSelect = { v -> onUpdate { it.copy(tunEngine = v) } }
            )
            HelperText(
                stringResource(if (config.tunEngine == TunEngineId.HEV) R.string.tunengine_help_hev else R.string.tunengine_help_singbox)
            )
            if (config.tunEngine == TunEngineId.SINGBOX_TUN && !singTunInBuild) {
                HelperText(stringResource(R.string.tunengine_missing), error = true)
            }
            InfoHint(stringResource(R.string.tunengine_info))
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
            // update19: the Kill Switch lives in this app's process. If Android ends the process, only Android's own
            // lockdown keeps traffic from leaving. Shown only while connected and only when lockdown is known to be off.
            val lockdown by AetherController.lockdown.collectAsState()
            if (config.killSwitchEnabled && lockdown == false) {
                HelperText(stringResource(R.string.lockdown_warning), error = true)
                TextButton(onClick = {
                    runCatching { ctx.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                }) { Text(stringResource(R.string.lockdown_open)) }
            }
            SwitchRow(
                stringResource(R.string.sw_udp), stringResource(R.string.sw_udp_sub),
                config.udpEnabled, { v -> onUpdate { it.copy(udpEnabled = v) } }
            )
            if (!config.udpEnabled) HelperText(stringResource(R.string.udp_off_dns_note))
            if (config.udpEnabled && config.effectiveChain.let { it == PrivacyChain.PSIPHON || it == PrivacyChain.TOR }) {
                HelperText(stringResource(R.string.udp_chain_note))
            }
            SwitchRow(
                stringResource(R.string.sw_notif_speed), stringResource(R.string.sw_notif_speed_sub),
                config.notifSpeed, { v -> onUpdate { it.copy(notifSpeed = v) } }
            )
            SwitchRow(
                stringResource(R.string.sw_power_saver), stringResource(R.string.sw_power_saver_sub),
                config.powerSaver, { v -> onUpdate { it.copy(powerSaver = v) } }
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
            // Language: empty = follow the phone (default). Changing it restarts this screen once, nothing else.
            val langCtx = LocalContext.current
            var lang by remember { mutableStateOf(AppLanguage.get(langCtx)) }
            SubLabel(stringResource(R.string.lbl_language))
            ChoiceChips(
                listOf(
                    stringResource(R.string.lang_system) to AppLanguage.SYSTEM,
                    stringResource(R.string.lang_fa) to AppLanguage.FA,
                    stringResource(R.string.lang_en) to AppLanguage.EN
                ),
                lang
            ) { v ->
                lang = v
                AppLanguage.set(langCtx, v)
                langCtx.findActivity()?.recreate()
            }
            // The hue is local while dragging and saved once on release: no storage write per pixel.
            var hue by remember { mutableFloatStateOf(hueOf(uiPrefs.customColor)) }
            val customOn = uiPrefs.themeId == Palettes.CUSTOM_ID
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
                val picked = hueColor(hue)
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.clip(MaterialTheme.shapes.medium)
                        .clickable {
                            onUpdateUi {
                                it.copy(
                                    themeId = Palettes.CUSTOM_ID,
                                    customColor = if (it.customColor != 0) it.customColor else picked
                                )
                            }
                        }
                        .padding(4.dp)
                ) {
                    Box(
                        Modifier.size(46.dp).clip(CircleShape).background(
                            if (customOn && uiPrefs.customColor != 0) {
                                Brush.linearGradient(listOf(Color(uiPrefs.customColor), Color(uiPrefs.customColor)))
                            } else {
                                Brush.sweepGradient(
                                    listOf(Color.Red, Color.Yellow, Color.Green, Color.Cyan, Color.Blue, Color.Magenta, Color.Red)
                                )
                            }
                        ),
                        contentAlignment = Alignment.Center
                    ) {
                        if (customOn) Icon(Icons.Rounded.Check, null, tint = Color.White)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.palette_custom), style = MaterialTheme.typography.labelSmall,
                        color = if (customOn) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            if (customOn) {
                Slider(
                    value = hue,
                    onValueChange = { hue = it },
                    onValueChangeFinished = {
                        val c = hueColor(hue)
                        onUpdateUi { it.copy(customColor = c) }
                    },
                    valueRange = 0f..359f
                )
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
            SubLabel(stringResource(R.string.lbl_connect_style))
            ChoiceChips(
                listOf(
                    stringResource(R.string.cs_blob) to ConnectStyle.BLOB,
                    stringResource(R.string.cs_pill) to ConnectStyle.PILL,
                    stringResource(R.string.cs_hero) to ConnectStyle.HERO,
                    stringResource(R.string.cs_ring) to ConnectStyle.RING,
                    stringResource(R.string.cs_bar) to ConnectStyle.BAR,
                    stringResource(R.string.cs_icon) to ConnectStyle.ICON,
                    stringResource(R.string.cs_switch) to ConnectStyle.SWITCH
                ),
                uiPrefs.connectStyle, { v -> onUpdateUi { it.copy(connectStyle = v) } }
            )
            HelperText(stringResource(R.string.connect_style_help))
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

private fun hueOf(argb: Int): Float {
    if (argb == 0) return 200f
    val hsl = FloatArray(3)
    ColorUtils.colorToHSL(argb, hsl)
    return hsl[0]
}

private fun hueColor(hue: Float): Int = ColorUtils.HSLToColor(floatArrayOf(hue, 0.62f, 0.40f))

private fun android.content.Context.findActivity(): android.app.Activity? {
    var c: android.content.Context = this
    while (c is android.content.ContextWrapper) {
        if (c is android.app.Activity) return c
        c = c.baseContext
    }
    return null
}
