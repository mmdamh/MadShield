package com.madshield.desktop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.madshield.app.core.FxAccount
import com.madshield.app.core.FxClient
import com.madshield.app.core.FxLocation
import com.madshield.app.core.FxPortPolicy
import com.madshield.app.core.flagEmoji
import com.madshield.app.util.RingLogBuffer
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun FoxyScreen(conn: Connection, settings: DesktopSettings, update: (DesktopSettings) -> Unit) {
    val scope = rememberCoroutineScope()
    val lang = LocalLang.current
    var status by remember { mutableStateOf(Strings.get(lang, "foxy.loading")) }
    var error by remember { mutableStateOf<String?>(null) }
    var accounts by remember { mutableStateOf<List<FxAccount>>(emptyList()) }
    var locations by remember { mutableStateOf<List<FxLocation>>(emptyList()) }
    var reload by remember { mutableStateOf(0) }

    // The core is shared: a Foxy connection owns it while it runs, otherwise this page starts its own.
    fun client(): FxClient {
        val ep = FoxyCore.endpoint?.takeIf { FoxyCore.alive } ?: FoxyCore.ensure()
        return ep.client()
    }

    LaunchedEffect(reload) {
        error = null
        status = Strings.get(lang, "foxy.loading")
        try {
            val (acc, locs) = withContext(Dispatchers.IO) {
                val ep = FoxyCore.endpoint?.takeIf { FoxyCore.alive } ?: FoxyCore.ensure()
                FoxyCore.awaitApi(ep, 20_000)
                val c = ep.client()
                val a = c.accounts()
                val l = if (a.isNotEmpty()) runCatching { c.locations() }.getOrDefault(emptyList()) else emptyList()
                a to l
            }
            accounts = acc
            locations = locs
            status = ""
        } catch (e: IOException) {
            status = ""
            error = e.message ?: "?"
            RingLogBuffer.append("[app] foxy page: ${e.message}")
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        PageHeader(t("foxy.title"))
        if (status.isNotEmpty()) Text(status, color = MaterialTheme.colorScheme.onSurfaceVariant)
        error?.let { Text(t("foxy.error") + ": " + it, color = MaterialTheme.colorScheme.error) }

        Text(t("foxy.account"), style = MaterialTheme.typography.titleMedium)
        if (accounts.isEmpty() && status.isEmpty()) Text(t("foxy.none"), color = MaterialTheme.colorScheme.onSurfaceVariant)
        for (a in accounts) {
            Panel(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(a.email, style = MaterialTheme.typography.titleSmall)
                    Text(a.status, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (!a.unlimited && a.limitBytes > 0) Text("${t("foxy.quota")}: ${formatBytes(a.usedBytes)} / ${formatBytes(a.limitBytes)}")
                    OutlinedButton(onClick = {
                        scope.launch {
                            withContext(Dispatchers.IO) { runCatching { client().removeAccount(a.id) } }
                            reload++
                        }
                    }) { Text(t("foxy.remove")) }
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = {
                scope.launch {
                    val c = withContext(Dispatchers.IO) { runCatching { client() }.getOrNull() }
                    if (c != null) FoxySignInWindow.open({ client() }, { Strings.get(lang, it) }) { reload++ }
                }
            }) { Text(t("foxy.signin")) }
            OutlinedButton(onClick = { reload++ }) { Text(t("foxy.refresh")) }
        }
        if (conn.state.value is ConnState.Connected && settings.engine == com.madshield.app.core.EngineKind.FIREFOX) {
            Text(t("foxy.connected.note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        if (locations.isNotEmpty()) {
            val current = locations.firstOrNull { it.code.equals(settings.fxLocation, true) }
            Choice(
                t("foxy.location"), current, listOf<FxLocation?>(null) + locations,
                { l -> if (l == null) t("foxy.recommended") else "${flagEmoji(l.code)} ${l.name}" + (if (l.city.isNotBlank()) " · ${l.city}" else "") }
            ) { l ->
                update(settings.copy(fxLocation = l?.code ?: ""))
                if (l != null) scope.launch { withContext(Dispatchers.IO) { runCatching { client().setLocation(l.code) } } }
            }
        }

        Spacer(Modifier.height(4.dp))
        Text(t("foxy.ports"), style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(settings.fxPortPolicy == FxPortPolicy.BLOCK, { update(settings.copy(fxPortPolicy = FxPortPolicy.BLOCK)) }, { Text(t("foxy.ports.block")) })
            FilterChip(settings.fxPortPolicy == FxPortPolicy.DIRECT, { update(settings.copy(fxPortPolicy = FxPortPolicy.DIRECT)) }, { Text(t("foxy.ports.direct")) })
        }
        Text(t("engine.applies"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
