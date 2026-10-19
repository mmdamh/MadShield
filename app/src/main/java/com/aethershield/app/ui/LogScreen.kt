package com.aethershield.app.ui

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.ui.components.BackTopBar
import com.aethershield.app.ui.components.HelperText
import com.aethershield.app.ui.components.MonoFamily
import com.aethershield.app.ui.components.SwitchRow
import com.aethershield.app.ui.components.rememberIsForeground
import com.aethershield.app.util.LogRedactor
import com.aethershield.app.util.RingLogBuffer
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filter

/**
 * The log view costs nothing while it is not on screen: the buffer never publishes anything by itself, this
 * screen asks "did it change?" twice a second, and only while it is composed AND the app is in the foreground.
 * New lines therefore show up within about half a second, and closing the page (or switching away from the
 * app) stops all work. The list follows the newest line only while the user is at the bottom.
 */
@Composable
fun LogScreen(onBack: () -> Unit) {
    val foreground by rememberIsForeground()
    var lines by remember { mutableStateOf(RingLogBuffer.snapshot()) }
    var removePrivate by remember { mutableStateOf(true) }
    var pinned by remember { mutableStateOf(true) }
    val listState = rememberLazyListState()
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val copied = stringResource(R.string.copied)

    LaunchedEffect(foreground) {
        if (!foreground) return@LaunchedEffect
        var seen = -1L
        while (true) {
            val v = RingLogBuffer.version
            if (v != seen) {
                seen = v
                lines = RingLogBuffer.snapshot()
            }
            delay(400)
        }
    }

    // A finished scroll gesture decides whether we keep following the newest line.
    LaunchedEffect(listState) {
        snapshotFlow { listState.isScrollInProgress }.filter { !it }.collect { pinned = !listState.canScrollForward }
    }
    LaunchedEffect(lines) {
        if (foreground && pinned && lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }

    Scaffold(topBar = {
        BackTopBar(stringResource(R.string.log_title), onBack, actions = {
            IconButton(onClick = {
                val text = if (removePrivate) LogRedactor.redactLines(lines) else lines
                clipboard.setText(AnnotatedString(text.joinToString("\n")))
                Toast.makeText(context, copied, Toast.LENGTH_SHORT).show()
            }) { Icon(Icons.Rounded.ContentCopy, contentDescription = stringResource(R.string.action_copy)) }
            IconButton(onClick = { RingLogBuffer.clear(); lines = emptyList() }) {
                Icon(Icons.Rounded.DeleteSweep, contentDescription = stringResource(R.string.action_clear))
            }
        })
    }) { padding ->
        Column(Modifier.padding(padding).padding(horizontal = 12.dp)) {
            HelperText(stringResource(R.string.log_note), Modifier.padding(bottom = 4.dp))
            SwitchRow(
                stringResource(R.string.log_redact_copy), stringResource(R.string.log_redact_copy_sub),
                removePrivate, { removePrivate = it }
            )
            SelectionContainer {
                LazyColumn(state = listState) {
                    itemsIndexed(lines, key = { index, _ -> index }) { _, line ->
                        Text(
                            line,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = MonoFamily, textDirection = TextDirection.Ltr
                            )
                        )
                    }
                }
            }
        }
    }
}
