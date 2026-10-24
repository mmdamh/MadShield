package com.aethershield.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.LinkError
import com.aethershield.app.core.LinkParse
import com.aethershield.app.core.ProxyLink
import com.aethershield.app.core.SettingsStore
import com.aethershield.app.ui.components.HelperText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Where the custom chain's share link is entered (vless:// vmess:// trojan:// ss://). The link holds a UUID or a
 * password, so it is saved only in the Keystore-backed store (SettingsStore.setChainLink), is hidden by default, and
 * is checked as you type: nothing can be saved that the app could not turn into a sing-box configuration.
 */
@Composable
fun CustomLinkEditor() {
    val appContext = LocalContext.current.applicationContext
    val store = remember { SettingsStore(appContext) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current

    var loaded by remember { mutableStateOf(false) }
    var saved by remember { mutableStateOf<String?>(null) }
    var text by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }
    var storeFailed by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val link = withContext(Dispatchers.IO) { store.getChainLink() }
        saved = link
        text = link ?: ""
        loaded = true
    }

    val parsed = remember(text) { if (text.isBlank()) null else ProxyLink.parse(text) }
    val dirty = text.trim() != (saved ?: "")

    Spacer(Modifier.height(10.dp))
    OutlinedTextField(
        value = text,
        onValueChange = { text = it; storeFailed = false },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        enabled = loaded,
        label = { Text(stringResource(R.string.link_label)) },
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = {
            TextButton(onClick = { show = !show }) {
                Text(stringResource(if (show) R.string.link_hide else R.string.link_show))
            }
        }
    )
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        TextButton(onClick = { clipboard.getText()?.text?.let { text = it.trim(); storeFailed = false } }) {
            Text(stringResource(R.string.link_paste))
        }
        Button(
            enabled = loaded && parsed is LinkParse.Ok && dirty,
            onClick = {
                val value = text.trim()
                scope.launch {
                    val ok = withContext(Dispatchers.IO) { store.setChainLink(value) }
                    if (ok) { saved = value; storeFailed = false } else storeFailed = true
                }
            }
        ) { Text(stringResource(R.string.action_save)) }
        if (saved != null) {
            TextButton(onClick = {
                scope.launch {
                    val ok = withContext(Dispatchers.IO) { store.setChainLink(null) }
                    if (ok) { saved = null; text = ""; storeFailed = false } else storeFailed = true
                }
            }) { Text(stringResource(R.string.link_remove)) }
        }
    }
    when {
        storeFailed -> HelperText(stringResource(R.string.link_keystore_fail), error = true)
        parsed is LinkParse.Err -> HelperText(linkErrorText(parsed), error = true)
        parsed is LinkParse.Ok -> HelperText(
            parsed.summary + (parsed.name.takeIf { it.isNotBlank() }?.let { "  ·  ${it.take(40)}" } ?: "") +
                if (dirty) "" else "  ·  " + stringResource(R.string.link_saved)
        )
        loaded && saved == null -> HelperText(stringResource(R.string.link_need), error = true)
    }
}

@Composable
private fun linkErrorText(e: LinkParse.Err): String {
    val base = stringResource(
        when (e.error) {
            LinkError.EMPTY -> R.string.link_err_empty
            LinkError.SCHEME -> R.string.link_err_scheme
            LinkError.MALFORMED -> R.string.link_err_malformed
            LinkError.PORT -> R.string.link_err_port
            LinkError.CREDENTIAL -> R.string.link_err_credential
            LinkError.XHTTP -> R.string.link_err_xhttp
            LinkError.TRANSPORT -> R.string.link_err_transport
            LinkError.SECURITY -> R.string.link_err_security
            LinkError.METHOD -> R.string.link_err_method
            LinkError.PLUGIN -> R.string.link_err_plugin
            LinkError.ENCRYPTION -> R.string.link_err_encryption
        }
    )
    return if (e.detail.isNotEmpty()) "$base (${e.detail})" else base
}
