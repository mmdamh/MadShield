package com.aethershield.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.Chain
import com.aethershield.app.core.ConnectionState
import com.aethershield.app.core.EngineConfig
import com.aethershield.app.core.PrivacyChain
import com.aethershield.app.core.Protocol
import com.aethershield.app.ui.components.ChoiceChips
import com.aethershield.app.ui.components.HelperText
import com.aethershield.app.ui.components.SectionCard

/**
 * The exit profile, on the home screen: Direct (the WARP exit itself), Psiphon (with a country), Tor, or your own link.
 * It used to be a settings section; it is the thing people switch most, so it lives next to Connect.
 *
 * The choice is stored in the same setting as before (privacyChain / psiphonRegion) and, as before, is read
 * when a connection starts. Psiphon and Tor carry TCP only and need a fixed WARP protocol, so picking one
 * while the protocol is "Smart" moves the protocol to MASQUE over HTTP/2 (TCP, which is what they need anyway).
 */
@Composable
fun ProfileCard(
    config: EngineConfig,
    state: ConnectionState,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit
) {
    val selected = config.effectiveChain

    fun select(chain: PrivacyChain) = onUpdate { cfg ->
        val needsFixedProtocol = chain != PrivacyChain.NONE && cfg.protocol == Protocol.SMART
        cfg.copy(privacyChain = chain, protocol = if (needsFixedProtocol) Protocol.MASQUE_H2 else cfg.protocol)
    }

    SectionCard(stringResource(R.string.sec_profile)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ProfileOption(
                Modifier.weight(1f), Icons.Rounded.Speed,
                stringResource(R.string.profile_direct), stringResource(R.string.profile_direct_sub),
                selected == PrivacyChain.NONE
            ) { select(PrivacyChain.NONE) }
            ProfileOption(
                Modifier.weight(1f), Icons.Rounded.Language,
                stringResource(R.string.profile_psiphon),
                Chain.normalizeRegion(config.psiphonRegion)?.let { regionLabel(it) } ?: stringResource(R.string.profile_psiphon_sub),
                selected == PrivacyChain.PSIPHON
            ) { select(PrivacyChain.PSIPHON) }
            ProfileOption(
                Modifier.weight(1f), Icons.Rounded.Security,
                stringResource(R.string.profile_tor), stringResource(R.string.profile_tor_sub),
                selected == PrivacyChain.TOR
            ) { select(PrivacyChain.TOR) }
            ProfileOption(
                Modifier.weight(1f), Icons.Rounded.Link,
                stringResource(R.string.profile_custom), stringResource(R.string.profile_custom_sub),
                selected == PrivacyChain.SINGBOX
            ) { select(PrivacyChain.SINGBOX) }
        }
        when (selected) {
            PrivacyChain.NONE -> HelperText(stringResource(R.string.chain_help))
            PrivacyChain.PSIPHON -> {
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(R.string.lbl_psiphon_region), style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.padding(bottom = 6.dp)
                )
                ChoiceChips(
                    listOf(stringResource(R.string.region_auto) to (null as String?)) +
                        Chain.REGIONS.map { regionLabel(it) to (it as String?) },
                    Chain.normalizeRegion(config.psiphonRegion),
                    onSelect = { v -> onUpdate { it.copy(psiphonRegion = v) } }
                )
                HelperText(stringResource(R.string.chain_psiphon_help))
            }
            PrivacyChain.TOR -> HelperText(stringResource(R.string.chain_tor_help))
            PrivacyChain.SINGBOX -> {
                HelperText(stringResource(R.string.chain_singbox_help))
                CustomLinkEditor()
            }
        }
        if (selected != PrivacyChain.NONE) HelperText(stringResource(R.string.profile_protocol_note))
        if (state !is ConnectionState.Idle) HelperText(stringResource(R.string.profile_apply_next))
    }
}

@Composable
private fun ProfileOption(
    modifier: Modifier,
    icon: ImageVector,
    title: String,
    sub: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    val cs = MaterialTheme.colorScheme
    Surface(
        onClick = onClick,
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        color = if (selected) cs.primaryContainer else cs.surfaceContainerHigh,
        border = if (selected) BorderStroke(1.5.dp, cs.primary) else null
    ) {
        Column(
            Modifier.padding(horizontal = 8.dp, vertical = 12.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                icon, null, modifier = Modifier.size(24.dp),
                tint = if (selected) cs.onPrimaryContainer else cs.onSurfaceVariant
            )
            Spacer(Modifier.height(6.dp))
            Text(
                title, style = MaterialTheme.typography.labelLarge, maxLines = 1,
                color = if (selected) cs.onPrimaryContainer else cs.onSurface
            )
            Text(
                sub, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis,
                textAlign = TextAlign.Center,
                color = if (selected) cs.onPrimaryContainer else cs.onSurfaceVariant
            )
        }
    }
}

/** "DE" -> flag emoji + code, so the chips are recognisable at a glance. */
private fun regionLabel(code: String): String {
    val flag = String(code.map { Character.toChars(0x1F1E6 + (it - 'A')) }.flatMap { it.asList() }.toCharArray())
    return "$flag $code"
}
