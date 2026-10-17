package com.aethershield.app.ui

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import com.aethershield.app.util.RingLogBuffer

@Composable
fun LogScreen(onBack: () -> Unit) {
    val lines by RingLogBuffer.lines.collectAsState()
    val listState = rememberLazyListState()
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val copied = stringResource(R.string.copied)

    // Follow the newest line, so a failing connect shows its reason without scrolling.
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }

    Scaffold(topBar = {
        BackTopBar(stringResource(R.string.log_title), onBack, actions = {
            IconButton(onClick = {
                clipboard.setText(AnnotatedString(lines.joinToString("\n")))
                Toast.makeText(context, copied, Toast.LENGTH_SHORT).show()
            }) { Icon(Icons.Rounded.ContentCopy, contentDescription = stringResource(R.string.action_copy)) }
            IconButton(onClick = { RingLogBuffer.clear() }) {
                Icon(Icons.Rounded.DeleteSweep, contentDescription = stringResource(R.string.action_clear))
            }
        })
    }) { padding ->
        Column(Modifier.padding(padding).padding(horizontal = 12.dp)) {
            HelperText(stringResource(R.string.log_note), Modifier.padding(bottom = 8.dp))
            SelectionContainer {
                LazyColumn(state = listState) {
                    items(lines) { line ->
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
