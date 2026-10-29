package com.madshield.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.*
import com.madshield.app.ui.components.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * DNS tab. Three different things are configured here and the text says so:
 *  0. Local DoH (update11): names resolved by THIS APP through DoH, in every mode. Independent of the core.
 *  1. Resolvers (AETHER_DNS): plain IPs only -- the stock core ignores anything else,
 *     so every entry is validated here and rejected ones are listed instead of vanishing.
 *  2. The ECH resolver (AETHER_ECH_DNS): the one place the core speaks DoH.
 * The speed test queries each resolver directly from the phone (not through the tunnel).
 *
 * update17 layout: the exit profile first, then "Secure DNS" (the DoH switch and a one-tap provider choice; every
 * other DoH option sits in "More options" right under it), then the resolvers and the ECH resolver as one-line cards
 * that unfold on tap. Every control that was here is still here; the long explanations moved behind an "i".
 */
@Composable
fun DnsScreen(
    config: EngineConfig,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit,
    contentPadding: PaddingValues,
    connectionState: ConnectionState = ConnectionState.Idle
) {
    val scope = rememberCoroutineScope()
    var text by remember(config.dnsResolvers) { mutableStateOf(config.dnsResolvers.joinToString("\n")) }
    val parsed = remember(text) { DnsConfig.parseList(text) }
    val canonical = parsed.valid.map { it.canonical }
    val dirty = canonical != config.dnsResolvers

    // ---- local DoH (update11)
    var dohText by remember(config.dohResolvers) { mutableStateOf(config.dohResolvers.joinToString("\n")) }
    val dohParsed = remember(dohText) { DohSpec.parseList(dohText) }
    val dohCanonical = dohParsed.valid.map { it.canonical }
    val dohDirty = dohCanonical != config.dohResolvers
    // the one-tap providers, in the same canonical form the list is saved in, so the matching chip lights up
    val dohProviders = remember {
        DohPresets.ALL.map { (name, value) -> name to (DohSpec.parseList(value).valid.firstOrNull()?.canonical ?: value) }
    }
    val customDoh = config.dohResolvers.isNotEmpty() && config.dohResolvers.joinToString("\n") !in dohProviders.map { it.second }
    val activeConfig by AetherController.active.collectAsState()
    var dohTesting by remember { mutableStateOf(false) }
    var dohResult by remember { mutableStateOf<Int?>(null) }

    var testing by remember { mutableStateOf(false) }
    var results by remember { mutableStateOf<List<Pair<DnsEntry, Long?>>>(emptyList()) }
    val mono = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFamily, textDirection = TextDirection.Ltr)

    Column(
        Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        PageHeader(stringResource(R.string.nav_dns), stringResource(R.string.dns_subtitle))

        // ------------------------------------------------------------ exit profile (moved from Home in 1.2.1)
        ProfileCard(config, connectionState, onUpdate)

        // ------------------------------------------------------------ secure DNS (local DoH)
        SectionCard(stringResource(R.string.sec_doh), icon = Icons.Rounded.Lock) {
            SwitchRow(
                label = stringResource(R.string.doh_sw),
                sub = stringResource(R.string.doh_sw_short),
                checked = config.dohOn,
                onCheckedChange = { v -> onUpdate { it.copy(dohOn = v) } }
            )
            InfoHint(stringResource(R.string.doh_sw_sub))
            if (config.dohOn && config.dohResolvers.isEmpty()) {
                HelperText(stringResource(R.string.doh_need_pick), error = true)
            }
            Spacer(Modifier.height(6.dp))
            ChoiceChips(
                dohProviders.map { (name, canonical) -> name to canonical } +
                    (if (customDoh) listOf(stringResource(R.string.doh_custom) to config.dohResolvers.joinToString("\n")) else emptyList<Pair<String, String>>()),
                selected = config.dohResolvers.joinToString("\n"),
                onSelect = { value ->
                    // a provider chip saves at once; the custom entry just stays what it is
                    if (value in dohProviders.map { it.second }) onUpdate { it.copy(dohResolvers = listOf(value)) }
                }
            )
            Spacer(Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = {
                        scope.launch {
                            val live = activeConfig
                            when {
                                connectionState !is ConnectionState.Connected -> dohResult = R.string.doh_test_not_connected
                                live?.dohActive != true -> dohResult = R.string.doh_test_reconnect
                                else -> {
                                    dohTesting = true
                                    dohResult = null
                                    val port = live?.socksPort ?: config.socksPort
                                    // A literal IP tests the tunnel alone; a name also needs the DoH lookup.
                                    val (ipOk, nameOk) = withContext(Dispatchers.IO) {
                                        SocksProbe.connectThrough(TunnelConfig.SOCKS_HOST, port, "1.1.1.1", 443) to
                                            SocksProbe.connectThrough(TunnelConfig.SOCKS_HOST, port, "www.cloudflare.com", 443)
                                    }
                                    dohResult = when {
                                        nameOk -> R.string.doh_test_ok
                                        ipOk -> R.string.doh_test_doh_fail
                                        else -> R.string.doh_test_tunnel_fail
                                    }
                                    dohTesting = false
                                }
                            }
                        }
                    },
                    enabled = !dohTesting
                ) { Text(stringResource(if (dohTesting) R.string.dns_testing else R.string.doh_test_btn)) }
            }
            if (dohTesting) {
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }
            dohResult?.let { HelperText(stringResource(it), error = it != R.string.doh_test_ok) }
            Spacer(Modifier.height(8.dp))
            MoreOptions {
                OutlinedTextField(
                    value = dohText,
                    onValueChange = { dohText = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp),
                    label = { Text(stringResource(R.string.lbl_doh_resolvers)) },
                    placeholder = { Text("https://cloudflare-dns.com/dns-query@address=1.1.1.1", style = mono) },
                    textStyle = mono,
                    isError = dohParsed.errors.isNotEmpty()
                )
                dohParsed.errors.forEach { (token, why) ->
                    HelperText(stringResource(R.string.doh_rejected, ltr(token), why), error = true)
                }
                InfoHint(stringResource(R.string.doh_help))
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { onUpdate { it.copy(dohResolvers = dohCanonical) } },
                        enabled = dohDirty && dohParsed.errors.isEmpty()
                    ) { Text(stringResource(R.string.action_save)) }
                    OutlinedButton(onClick = { dohText = config.dohResolvers.joinToString("\n") }, enabled = dohDirty) {
                        Text(stringResource(R.string.action_revert))
                    }
                }
                Spacer(Modifier.height(6.dp))
                SwitchRow(
                    label = stringResource(R.string.doh_via_tor),
                    sub = stringResource(R.string.doh_via_tor_sub),
                    checked = config.dohViaTor,
                    onCheckedChange = { v -> onUpdate { it.copy(dohViaTor = v) } }
                )
                SwitchRow(
                    label = stringResource(R.string.doh_stale),
                    sub = stringResource(R.string.doh_stale_sub),
                    checked = config.dohServeStale,
                    onCheckedChange = { v -> onUpdate { it.copy(dohServeStale = v) } }
                )
                SwitchRow(
                    label = stringResource(R.string.doh_direct),
                    sub = stringResource(R.string.doh_direct_sub),
                    checked = config.dohForDirect,
                    onCheckedChange = { v -> onUpdate { it.copy(dohForDirect = v) } }
                )
                InfoHint(stringResource(R.string.doh_limits))
            }
        }

        // ------------------------------------------------------------ plain resolvers (presets, custom list, speed test)
        FoldCard(
            title = stringResource(R.string.sec_dns_resolvers),
            summary = when {
                config.dnsResolvers.isEmpty() -> stringResource(R.string.dns_default)
                else -> DnsPresets.matching(config.dnsResolvers)?.name
                    ?: stringResource(R.string.dns_custom_count, config.dnsResolvers.size)
            },
            icon = Icons.Rounded.Dns
        ) {
            ChoiceChips(
                listOf(stringResource(R.string.dns_default) to emptyList<String>()) +
                    DnsPresets.ALL.map { it.name to it.servers },
                selected = config.dnsResolvers,
                onSelect = { servers -> onUpdate { it.copy(dnsResolvers = servers) } }
            )
            InfoHint(stringResource(R.string.dns_presets_help))
            Spacer(Modifier.height(4.dp))
            MoreOptions(label = stringResource(R.string.sec_dns_custom)) {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp),
                    label = { Text(stringResource(R.string.lbl_resolvers)) },
                    placeholder = { Text("1.1.1.1\n9.9.9.9:53\n[2606:4700:4700::1111]:53", style = mono) },
                    textStyle = mono,
                    isError = parsed.rejected.isNotEmpty()
                )
                if (parsed.rejected.isNotEmpty()) {
                    HelperText(
                        stringResource(R.string.dns_rejected, ltr(parsed.rejected.joinToString("  "))),
                        error = true
                    )
                }
                InfoHint(stringResource(R.string.dns_custom_help))
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { onUpdate { it.copy(dnsResolvers = canonical) } },
                        enabled = dirty && parsed.rejected.isEmpty()
                    ) { Text(stringResource(R.string.action_save)) }
                    OutlinedButton(onClick = { text = config.dnsResolvers.joinToString("\n") }, enabled = dirty) {
                        Text(stringResource(R.string.action_revert))
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            // ---- speed test
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(Icons.Rounded.Speed, null, tint = MaterialTheme.colorScheme.primary)
                Text(stringResource(R.string.sec_dns_test), style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                FilledTonalButton(
                    onClick = {
                        val targets = parsed.valid.ifEmpty {
                            DnsPresets.ALL.flatMap { it.servers }.mapNotNull { DnsConfig.parse(it) }
                        }
                        scope.launch {
                            testing = true
                            results = emptyList()
                            val measured = withContext(Dispatchers.IO) {
                                targets.map { e -> async { e to DnsProbe.measure(e) } }.awaitAll()
                            }
                            results = measured.sortedWith(compareBy({ it.second == null }, { it.second ?: 0L }))
                            testing = false
                        }
                    },
                    enabled = !testing
                ) { Text(stringResource(if (testing) R.string.dns_testing else R.string.dns_test_btn)) }
            }
            if (testing) {
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }
            results.forEach { (entry, ms) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(ltr(entry.canonical), style = mono, modifier = Modifier.weight(1f))
                    Text(
                        if (ms != null) ltr("$ms ms") else stringResource(R.string.dns_no_answer),
                        style = MaterialTheme.typography.labelLarge,
                        color = if (ms != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                    )
                }
            }
            val fastest = results.filter { it.second != null }.take(2).map { it.first.canonical }
            if (fastest.isNotEmpty() && !testing) {
                Spacer(Modifier.height(8.dp))
                FilledTonalButton(onClick = { onUpdate { it.copy(dnsResolvers = fastest) } }) {
                    Text(stringResource(R.string.dns_use_fastest))
                }
            }
            InfoHint(stringResource(R.string.dns_test_help))
        }

        // ------------------------------------------------------------ ECH resolver
        FoldCard(
            title = stringResource(R.string.sec_dns_ech),
            summary = config.echDns?.let { ltr(it) } ?: stringResource(R.string.dns_default),
            icon = Icons.Rounded.Lock
        ) {
            var ech by remember(config.echDns) { mutableStateOf(config.echDns ?: "") }
            val valid = ech.isBlank() || DnsConfig.isValidEchResolver(ech)
            ChoiceChips(
                DnsPresets.ECH_RESOLVERS.map { (name, value) -> name to value },
                selected = ech.trim(),
                onSelect = { ech = it }
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = ech, onValueChange = { ech = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.lbl_ech_resolver)) },
                placeholder = { Text("https://cloudflare-dns.com/dns-query", style = mono) },
                textStyle = mono,
                singleLine = true,
                isError = !valid,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
            )
            if (!valid) HelperText(stringResource(R.string.ech_invalid), error = true)
            InfoHint(stringResource(R.string.ech_help))
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = { onUpdate { it.copy(echDns = ech.trim().ifBlank { null }) } },
                enabled = valid && ech.trim() != (config.echDns ?: "")
            ) { Text(stringResource(R.string.action_save)) }
        }
        Spacer(Modifier.height(NavClearance))
    }
}

/** A "More options" row that unfolds the rarely-used controls of a card right where they belong. */
@Composable
private fun MoreOptions(label: String? = null, content: @Composable ColumnScope.() -> Unit) {
    var open by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth()) {
        TextButton(onClick = { open = !open }) {
            Text(
                (label ?: stringResource(R.string.more_options)) + if (open) "  ▴" else "  ▾",
                style = MaterialTheme.typography.labelLarge
            )
        }
        androidx.compose.animation.AnimatedVisibility(visible = open) {
            Column(Modifier.fillMaxWidth(), content = content)
        }
    }
}
