package com.madshield.app.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.madshield.app.R
import com.madshield.app.core.Chain
import com.madshield.app.core.ConnectionState
import com.madshield.app.core.EngineConfig
import com.madshield.app.core.PrivacyChain
import com.madshield.app.core.Protocol
import com.madshield.app.ui.components.CookieBadge
import com.madshield.app.ui.components.InfoHint
import com.madshield.app.ui.components.SectionCard
import java.util.Locale

/**
 * The exit profile (DNS tab): Direct (the WARP exit itself), Psiphon (with a country), Tor, or your own link(s).
 *
 * update17 look: one slim selector with a single word per choice (the old tiles cut their sub-lines to "WARP ...",
 * "Slow, p..."), and ONE panel under it that shows only the chosen profile: a cookie badge with what you are using
 * right now, and the one action that profile has (change country / pick a link). The long explanations moved behind
 * an "i". The Psiphon country list is a searchable sheet instead of 27 chips on the page.
 *
 * The behaviour is exactly as before: the choice is the same setting (privacyChain / psiphonRegion) and is read
 * when a connection starts. Psiphon, Tor and Link carry TCP only and need a fixed WARP protocol, so picking one
 * while the protocol is "Smart" moves the protocol to MASQUE over HTTP/2 (TCP, which is what they need anyway).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileCard(
    config: EngineConfig,
    state: ConnectionState,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit
) {
    val selected = config.effectiveChain
    var picker by rememberSaveable { mutableStateOf(false) }

    fun select(chain: PrivacyChain) = onUpdate { cfg ->
        val needsFixedProtocol = chain != PrivacyChain.NONE && cfg.protocol == Protocol.SMART
        cfg.copy(privacyChain = chain, protocol = if (needsFixedProtocol) Protocol.MASQUE_H2 else cfg.protocol)
    }

    SectionCard(stringResource(R.string.sec_profile)) {
        ProfileSegments(selected) { select(it) }
        Spacer(Modifier.height(14.dp))
        AnimatedContent(targetState = selected, label = "profile-body") { chain ->
            Column(Modifier.fillMaxWidth()) {
                when (chain) {
                    PrivacyChain.NONE -> {
                        ExitRow(
                            icon = { Icon(Icons.Rounded.Speed, null, tint = MaterialTheme.colorScheme.onPrimaryContainer) },
                            title = stringResource(R.string.profile_direct),
                            subtitle = stringResource(R.string.profile_direct_line)
                        )
                        InfoHint(stringResource(R.string.chain_help))
                    }
                    PrivacyChain.PSIPHON -> {
                        val region = Chain.normalizeRegion(config.psiphonRegion)
                        ExitRow(
                            icon = {
                                if (region != null) Text(flagOf(region), fontSize = 26.sp)
                                else Icon(Icons.Rounded.Language, null, tint = MaterialTheme.colorScheme.onPrimaryContainer)
                            },
                            title = region?.let { countryName(it) } ?: stringResource(R.string.region_auto),
                            subtitle = stringResource(R.string.profile_psiphon_line),
                            trailing = {
                                FilledTonalButton(onClick = { picker = true }) { Text(stringResource(R.string.region_change)) }
                            }
                        )
                        InfoHint(stringResource(R.string.chain_psiphon_help))
                    }
                    PrivacyChain.TOR -> {
                        ExitRow(
                            icon = { Icon(Icons.Rounded.Security, null, tint = MaterialTheme.colorScheme.onPrimaryContainer) },
                            title = stringResource(R.string.profile_tor),
                            subtitle = stringResource(R.string.profile_tor_line)
                        )
                        InfoHint(stringResource(R.string.chain_tor_help))
                    }
                    PrivacyChain.SINGBOX -> {
                        CustomLinkEditor()
                        InfoHint(stringResource(R.string.chain_singbox_help))
                    }
                }
            }
        }
        if (selected != PrivacyChain.NONE) InfoHint(stringResource(R.string.profile_protocol_note))
        if (state !is ConnectionState.Idle) {
            Text(
                stringResource(R.string.profile_apply_next),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }

    if (picker) {
        ModalBottomSheet(
            onDismissRequest = { picker = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            CountryPicker(
                current = Chain.normalizeRegion(config.psiphonRegion),
                onPick = { code ->
                    onUpdate { it.copy(psiphonRegion = code) }
                    picker = false
                }
            )
        }
    }
}

/** The four choices as one pill-shaped selector: icon over a one-word label, so nothing is ever cut off. */
@Composable
private fun ProfileSegments(selected: PrivacyChain, onSelect: (PrivacyChain) -> Unit) {
    val cs = MaterialTheme.colorScheme
    val choices: List<Triple<PrivacyChain, ImageVector, Int>> = listOf(
        Triple(PrivacyChain.NONE, Icons.Rounded.Speed, R.string.profile_direct),
        Triple(PrivacyChain.PSIPHON, Icons.Rounded.Language, R.string.profile_psiphon),
        Triple(PrivacyChain.TOR, Icons.Rounded.Security, R.string.profile_tor),
        Triple(PrivacyChain.SINGBOX, Icons.Rounded.Link, R.string.profile_custom)
    )
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(26.dp)).background(cs.surfaceContainerHigh).padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        choices.forEach { (chain, icon, label) ->
            val on = chain == selected
            val bg by animateColorAsState(if (on) cs.primary else Color.Transparent, label = "seg-bg")
            val fg by animateColorAsState(if (on) cs.onPrimary else cs.onSurfaceVariant, label = "seg-fg")
            Surface(
                onClick = { onSelect(chain) },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(22.dp),
                color = bg,
                contentColor = fg
            ) {
                Column(Modifier.padding(vertical = 10.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(icon, null, modifier = Modifier.size(22.dp))
                    Spacer(Modifier.height(4.dp))
                    Text(stringResource(label), style = MaterialTheme.typography.labelMedium, maxLines = 1)
                }
            }
        }
    }
}

/** "What you are using now": the cookie badge, a title, one line under it and (optionally) the profile's one action. */
@Composable
private fun ExitRow(
    icon: @Composable BoxScope.() -> Unit,
    title: String,
    subtitle: String,
    trailing: (@Composable () -> Unit)? = null
) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        CookieBadge(56.dp, content = icon)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (trailing != null) {
            Spacer(Modifier.width(8.dp))
            trailing()
        }
    }
}

/** The Psiphon exit country list: searchable by name (in the app's language) or by code, "Automatic" first. */
@Composable
private fun CountryPicker(current: String?, onPick: (String?) -> Unit) {
    val cs = MaterialTheme.colorScheme
    var query by remember { mutableStateOf("") }
    val all = remember {
        val collator = java.text.Collator.getInstance(Locale.getDefault())
        Chain.REGIONS.map { it to countryName(it) }.sortedWith { a, b -> collator.compare(a.second, b.second) }
    }
    val shown = remember(query) {
        val q = query.trim().lowercase()
        if (q.isEmpty()) all else all.filter { it.first.lowercase().contains(q) || it.second.lowercase().contains(q) }
    }
    Column(Modifier.fillMaxWidth().fillMaxHeight(0.85f).padding(horizontal = 16.dp)) {
        Text(stringResource(R.string.lbl_psiphon_region), style = MaterialTheme.typography.titleLarge, color = cs.onSurface)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            leadingIcon = { Icon(Icons.Rounded.Search, null) },
            placeholder = { Text(stringResource(R.string.region_search)) }
        )
        Spacer(Modifier.height(8.dp))
        LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
            if (query.isBlank()) {
                item(key = "auto") {
                    CountryRow(Icons.Rounded.Language, null, stringResource(R.string.region_auto), current == null) { onPick(null) }
                }
            }
            items(shown, key = { it.first }) { (code, name) ->
                CountryRow(null, flagOf(code), name, current == code, code) { onPick(code) }
            }
            item(key = "end") { Spacer(Modifier.height(24.dp).navigationBarsPadding()) }
        }
    }
}

@Composable
private fun CountryRow(
    icon: ImageVector?,
    flag: String?,
    name: String,
    on: Boolean,
    code: String? = null,
    onClick: () -> Unit
) {
    val cs = MaterialTheme.colorScheme
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp))
            .background(if (on) cs.primaryContainer else Color.Transparent)
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.width(36.dp), contentAlignment = Alignment.Center) {
            if (flag != null) Text(flag, fontSize = 24.sp) else if (icon != null) Icon(icon, null, tint = cs.onSurfaceVariant)
        }
        Spacer(Modifier.width(12.dp))
        Text(
            name, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f),
            color = if (on) cs.onPrimaryContainer else cs.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        if (code != null) {
            Text(code, style = MaterialTheme.typography.labelMedium, color = if (on) cs.onPrimaryContainer else cs.onSurfaceVariant)
            Spacer(Modifier.width(8.dp))
        }
        if (on) Icon(Icons.Rounded.Check, null, tint = cs.onPrimaryContainer)
    }
}

/** "DE" -> its flag emoji. */
private fun flagOf(code: String): String =
    String(code.map { Character.toChars(0x1F1E6 + (it - 'A')) }.flatMap { it.asList() }.toCharArray())

/** "DE" -> "Germany" / "آلمان", in the app's language; falls back to the code if the system has no name for it. */
private fun countryName(code: String): String {
    val name = Locale("", code).getDisplayCountry(Locale.getDefault())
    return if (name.isBlank() || name.equals(code, ignoreCase = true)) code else name
}
