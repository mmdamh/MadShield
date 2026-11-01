package com.madshield.app.ui

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.AetherController
import com.madshield.app.core.CleanPolicy
import com.madshield.app.core.ConnectionState
import com.madshield.app.core.StorageCleaner
import com.madshield.app.core.StoragePrefs
import com.madshield.app.core.StorageReport
import com.madshield.app.ui.components.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/** What the app keeps on the phone, and the leftovers clean-up. Sizes are read once when the page opens. */
@Composable
fun StorageScreen(prefs: StoragePrefs, onUpdate: ((StoragePrefs) -> StoragePrefs) -> Unit, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by AetherController.state.collectAsState()
    val idle = state is ConnectionState.Idle
    var report by remember { mutableStateOf<StorageReport?>(null) }
    var reclaim by remember { mutableLongStateOf(0L) }
    var tick by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }

    LaunchedEffect(tick, prefs.maxAgeDays, prefs.keepEngineData) {
        withContext(Dispatchers.IO) {
            report = StorageCleaner.report(ctx.filesDir, ctx.cacheDir, ctx.applicationInfo.dataDir?.let { java.io.File(it) })
            reclaim = StorageCleaner.reclaimable(ctx.filesDir, ctx.cacheDir, prefs.policy(), System.currentTimeMillis())
        }
    }

    Scaffold(topBar = { BackTopBar(stringResource(R.string.storage_title), onBack) }) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            val r = report
            SectionCard(stringResource(R.string.storage_used)) {
                Text(formatBytes(r?.total ?: 0L), style = MaterialTheme.typography.displaySmall, color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.height(8.dp))
                if (r != null) {
                    Line(stringResource(R.string.storage_rules), r.rules)
                    Line(stringResource(R.string.storage_engine), r.engine)
                    Line(stringResource(R.string.storage_cache), r.cache)
                    Line(stringResource(R.string.storage_settings), r.settings)
                }
            }
            SectionCard(stringResource(R.string.storage_auto_title)) {
                SwitchRow(
                    stringResource(R.string.storage_auto), stringResource(R.string.storage_auto_sub),
                    prefs.autoClean, { v -> onUpdate { it.copy(autoClean = v) } }
                )
                Text(stringResource(R.string.storage_older_than), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.height(4.dp))
                ChoiceChips(
                    StoragePrefs.CHOICES.map { stringResource(R.string.storage_days, it) to it }, prefs.maxAgeDays
                ) { d -> onUpdate { it.copy(maxAgeDays = d) } }
                SwitchRow(
                    stringResource(R.string.storage_keep_engine), stringResource(R.string.storage_keep_engine_sub),
                    prefs.keepEngineData, { v -> onUpdate { it.copy(keepEngineData = v) } }
                )
                HelperText(
                    if (prefs.lastCleanMs > 0L)
                        stringResource(R.string.storage_last, DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(prefs.lastCleanMs)))
                    else stringResource(R.string.storage_never)
                )
            }
            Button(
                onClick = {
                    busy = true
                    scope.launch {
                        val freed = withContext(Dispatchers.IO) {
                            StorageCleaner.clean(ctx.filesDir, ctx.cacheDir, CleanPolicy(0, prefs.keepEngineData), System.currentTimeMillis())
                        }
                        busy = false
                        tick++
                        Toast.makeText(ctx, ctx.getString(R.string.storage_cleaned, formatBytes(freed)), Toast.LENGTH_SHORT).show()
                    }
                },
                enabled = idle && !busy, modifier = Modifier.fillMaxWidth()
            ) { Text(stringResource(R.string.storage_clean_now)) }
            if (!idle) HelperText(stringResource(R.string.storage_disconnect_first))
            HelperText(stringResource(R.string.storage_safe))
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun Line(label: String, bytes: Long) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(formatBytes(bytes), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}
