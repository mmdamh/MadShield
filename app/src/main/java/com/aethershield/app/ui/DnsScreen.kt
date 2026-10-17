package com.aethershield.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.*
import com.aethershield.app.ui.components.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * DNS tab. Two different things are configured here and the text says so:
 *  1. Resolvers (AETHER_DNS): plain IPs only -- the stock core ignores anything else,
 *     so every entry is validated here and rejected ones are listed instead of vanishing.
 *  2. The ECH resolver (AETHER_ECH_DNS): the one place the core speaks DoH.
 * The speed test queries each resolver directly from the phone (not through the tunnel).
 */
@Composable
fun DnsScreen(
    config: EngineConfig,
    onUpdate: ((EngineConfig) -> EngineConfig) -> Unit,
    contentPadding: PaddingValues
) {
    val scope = rememberCoroutineScope()
    var text by remember(config.dnsResolvers) { mutableStateOf(config.dnsResolvers.joinToString("\n")) }
    val parsed = remember(text) { DnsConfig.parseList(text) }
    val canonical = parsed.valid.map { it.canonical }
    val dirty = canonical != config.dnsResolvers

    var testing by remember { mutableStateOf(false) }
    var results by remember { mutableStateOf<List<Pair<DnsEntry, Long?>>>(emptyList()) }
    val mono = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFamily, textDirection = TextDirection.Ltr)

    Column(
        Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        PageHeader(stringResource(R.string.nav_dns), stringResource(R.string.dns_subtitle))

        // ------------------------------------------------------------ presets
        SectionCard(stringResource(R.string.sec_dns_presets)) {
            ChoiceChips(
                listOf(stringResource(R.string.dns_default) to emptyList<String>()) +
                    DnsPresets.ALL.map { it.name to it.servers },
                selected = config.dnsResolvers,
                onSelect = { servers -> onUpdate { it.copy(dnsResolvers = servers) } }
            )
            HelperText(stringResource(R.string.dns_presets_help))
        }

        // ------------------------------------------------------------ editor
        SectionCard(stringResource(R.string.sec_dns_custom)) {
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
            HelperText(stringResource(R.string.dns_custom_help))
            Spacer(Modifier.height(10.dp))
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

        // ------------------------------------------------------------ speed test
        SectionCard(stringResource(R.string.sec_dns_test)) {
            Button(
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
            HelperText(stringResource(R.string.dns_test_help))
        }

        // ------------------------------------------------------------ ECH resolver
        SectionCard(stringResource(R.string.sec_dns_ech)) {
            var ech by remember(config.echDns) { mutableStateOf(config.echDns ?: "") }
            val valid = ech.isBlank() || DnsConfig.isValidEchResolver(ech)
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
            HelperText(stringResource(R.string.ech_help))
            Spacer(Modifier.height(8.dp))
            ChoiceChips(
                DnsPresets.ECH_RESOLVERS.map { (name, value) -> name to value },
                selected = ech.trim(),
                onSelect = { ech = it }
            )
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = { onUpdate { it.copy(echDns = ech.trim().ifBlank { null }) } },
                enabled = valid && ech.trim() != (config.echDns ?: "")
            ) { Text(stringResource(R.string.action_save)) }
        }
        Spacer(Modifier.height(NavClearance))
    }
}
