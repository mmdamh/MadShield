package com.madshield.app.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import com.madshield.app.R
import com.madshield.app.core.FxClient
import com.madshield.app.core.FxJson
import com.madshield.app.core.FxReauth
import com.madshield.app.core.FxReauthGate
import com.madshield.app.core.FxRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Renews the account's access token when Mozilla's bot check (Fastly) wants an image CAPTCHA that nobody could answer in the
 * background. The core does the renewal ([FxClient.reauthStart]); this dialog shows its picture and sends the characters back.
 * Nothing is stored. While it is open the connection's health loop does not restart the core ([FxReauthGate]).
 *
 * [onClose] gets true when the sign-in was renewed.
 */
@Composable
fun FxRenewDialog(accountId: String, client: () -> FxClient, onClose: (renewed: Boolean) -> Unit) {
    val scope = rememberCoroutineScope()
    var view by remember { mutableStateOf<FxReauth?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var attempt by remember { mutableStateOf(0) }
    var sending by remember { mutableStateOf(false) }

    LaunchedEffect(attempt) {
        problem = null
        view = null
        FxReauthGate.hold()
        try {
            var cur = withContext(Dispatchers.IO) { client().reauthStart(accountId) }
            view = cur
            while (!cur.finished) {
                delay(700)
                FxReauthGate.hold() // still being answered: the hold is kept while the dialog polls
                cur = withContext(Dispatchers.IO) { client().reauthGet() }
                view = cur
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            problem = e.message ?: e.javaClass.simpleName
        } finally {
            FxReauthGate.release()
        }
    }
    DisposableEffect(Unit) {
        onDispose {
            FxReauthGate.release()
            // a renewal still waiting for its answer ends with the dialog
            // (the live core only: a page that is closing has already stopped its own, and must not start another)
            Thread { runCatching { FxRuntime.endpoint?.client()?.reauthCancel() } }.start()
        }
    }

    val v = view
    AlertDialog(
        onDismissRequest = {},
        properties = DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = false),
        title = { Text(stringResource(R.string.fx_renew_title)) },
        text = {
            Column {
                when {
                    problem != null -> Text(stringResource(R.string.fx_renew_failed, problem ?: ""), color = MaterialTheme.colorScheme.error)
                    v == null || v.state == "running" || v.state == "idle" -> {
                        Text(stringResource(R.string.fx_renew_working), style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(10.dp))
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                    }
                    v != null && v.waitingCaptcha -> {
                        Text(stringResource(R.string.fx_renew_captcha), style = MaterialTheme.typography.bodyMedium)
                        val bmp = remember(v.id) {
                            FxJson.dataUrlBytes(v.image)?.let { b -> runCatching { BitmapFactory.decodeByteArray(b, 0, b.size) }.getOrNull() }
                        }
                        if (bmp != null) {
                            Spacer(Modifier.height(8.dp))
                            Image(bmp.asImageBitmap(), contentDescription = null, modifier = Modifier.height(100.dp))
                        }
                        var text by remember(v.id) { mutableStateOf("") }
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = text, onValueChange = { text = it }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                            label = { Text(stringResource(R.string.fx_renew_field)) },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text)
                        )
                        Spacer(Modifier.height(8.dp))
                        Button(
                            enabled = !sending && text.isNotBlank(),
                            onClick = {
                                val id = v.id
                                val answer = text.trim()
                                sending = true
                                scope.launch {
                                    try { withContext(Dispatchers.IO) { client().reauthAnswer(id, answer) } }
                                    catch (_: Exception) { /* the next poll shows what happened (a new picture, or the result) */ }
                                    finally { sending = false }
                                }
                            }
                        ) { Text(stringResource(R.string.fx_renew_send)) }
                    }
                    v != null && v.state == "done" -> Text(
                        stringResource(if (v.renewed) R.string.fx_renew_done else R.string.fx_renew_still_good),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    else -> Text(stringResource(R.string.fx_renew_failed, v?.error.orEmpty().ifEmpty { "?" }), color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            val done = v?.state == "done" && problem == null
            if (done) TextButton(onClick = { onClose(true) }) { Text(stringResource(R.string.fx_renew_close)) }
            else if (problem != null || v?.state == "failed") TextButton(onClick = { attempt++ }) { Text(stringResource(R.string.action_retry)) }
        },
        dismissButton = {
            val done = v?.state == "done" && problem == null
            if (!done) TextButton(onClick = { onClose(false) }) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}
