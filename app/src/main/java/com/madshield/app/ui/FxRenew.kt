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
import com.madshield.app.core.FxRenewFlow
import com.madshield.app.core.FxRenewUi
import com.madshield.app.core.FxReauthCodes
import com.madshield.app.core.FxReauthGate
import com.madshield.app.core.FxRuntime
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Renews the account's access token when Mozilla's bot check (Fastly) wants an image CAPTCHA that nobody could answer in the
 * background. The core does the renewal ([FxClient.reauthStart]); this dialog shows its picture and sends the characters back.
 * Nothing is stored. While it is open the connection's health loop does not restart the core ([FxReauthGate]).
 *
 * What is shown follows [FxRenewFlow] (one instance per attempt, named by the operation the core started): one answer goes
 * out per picture, the answer field is locked while it is out, a view of another operation ends this one, and closing the
 * dialog cancels exactly the operation it started. "Sent" never means "correct": the dialog says what the core reports.
 *
 * [onClose] gets true when the sign-in was renewed.
 */
@Composable
fun FxRenewDialog(accountId: String, client: () -> FxClient, onClose: (renewed: Boolean) -> Unit) {
    val scope = rememberCoroutineScope()
    var attempt by remember { mutableStateOf(0) }
    val flow = remember(attempt) { FxRenewFlow() }
    var ui by remember(attempt) { mutableStateOf<FxRenewUi>(FxRenewUi.Connecting) }

    LaunchedEffect(flow) {
        FxReauthGate.hold()
        try {
            // not cancellable: once the core was asked, the operation it names must reach the flow, so closing the dialog
            // at this very moment still cancels it (below)
            val first = try {
                withContext(Dispatchers.IO + NonCancellable) { client().reauthStart(accountId) }
            } catch (e: FxClient.ApiException) {
                ui = flow.startFailed(e.code, e.message ?: ""); return@LaunchedEffect
            } catch (e: Exception) {
                ui = flow.startFailed("", e.message ?: e.javaClass.simpleName); return@LaunchedEffect
            }
            ui = flow.started(first)
            ensureActive()
            while (flow.polling) {
                delay(700)
                FxReauthGate.hold() // still being answered: the hold is kept while the dialog polls
                try {
                    val view = withContext(Dispatchers.IO) { client().reauthGet() }
                    ui = flow.apply(view)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    ui = flow.pollFailed(e.message ?: e.javaClass.simpleName)
                }
            }
        } catch (e: CancellationException) {
            flow.cancelTarget()?.let { cancelRenewal(it) }
            throw e
        } finally {
            if (flow.cancelTarget() == null) FxReauthGate.release()
        }
    }
    DisposableEffect(flow) {
        onDispose {
            FxReauthGate.release()
            // a renewal this dialog started and that is still running ends with it, and only that one
            flow.cancelTarget()?.let { cancelRenewal(it) }
        }
    }

    val cur = ui
    AlertDialog(
        onDismissRequest = {},
        properties = DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = false),
        title = { Text(stringResource(R.string.fx_renew_title)) },
        text = {
            Column {
                when (cur) {
                    is FxRenewUi.Connecting -> Working(R.string.fx_renew_working)
                    is FxRenewUi.Submitting -> Working(R.string.fx_renew_submitting)
                    is FxRenewUi.Verifying -> Working(R.string.fx_renew_verifying)
                    is FxRenewUi.Captcha -> CaptchaBody(cur) { id, answer ->
                        // one answer per picture: the flow refuses a second tap, and the picture it was for
                        if (flow.beginSubmit(id, answer)) {
                            ui = flow.ui
                            val op = flow.op
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { client().reauthAnswer(op, id, answer) }
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: FxClient.ApiException) {
                                    ui = flow.submitFailed(id, e.code, e.message ?: "")
                                } catch (e: Exception) {
                                    ui = flow.submitFailed(id, "", e.message ?: e.javaClass.simpleName)
                                }
                            }
                        }
                    }
                    is FxRenewUi.Success -> Text(
                        stringResource(if (cur.renewed) R.string.fx_renew_done else R.string.fx_renew_still_good),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    is FxRenewUi.Failed -> Text(failureText(cur), color = MaterialTheme.colorScheme.error)
                    is FxRenewUi.Cancelled -> Text(stringResource(R.string.fx_renew_cancelled), style = MaterialTheme.typography.bodyMedium)
                    is FxRenewUi.TimedOut -> Text(stringResource(R.string.fx_renew_timed_out), color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            when (cur) {
                is FxRenewUi.Success -> TextButton(onClick = { onClose(true) }) { Text(stringResource(R.string.fx_renew_close)) }
                is FxRenewUi.Failed, is FxRenewUi.TimedOut, is FxRenewUi.Cancelled ->
                    TextButton(onClick = { attempt++ }) { Text(stringResource(R.string.action_retry)) }
                else -> {}
            }
        },
        dismissButton = {
            if (cur !is FxRenewUi.Success) TextButton(onClick = { onClose(false) }) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}

/** Ends operation [op] in the live core without waiting for it (a closing page cannot wait, and must not start a core). */
private fun cancelRenewal(op: String) {
    Thread { runCatching { FxRuntime.endpoint?.client()?.reauthCancel(op) } }.start()
}

@Composable
private fun Working(text: Int) {
    Text(stringResource(text), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(10.dp))
    LinearProgressIndicator(Modifier.fillMaxWidth())
}

@Composable
private fun CaptchaBody(pic: FxRenewUi.Captcha, onSend: (id: String, answer: String) -> Unit) {
    Text(
        stringResource(if (pic.another) R.string.fx_renew_another else R.string.fx_renew_captcha),
        style = MaterialTheme.typography.bodyMedium
    )
    if (pic.round > 1) {
        Text(stringResource(R.string.fx_renew_round, pic.round), style = MaterialTheme.typography.labelSmall)
    }
    val bmp = remember(pic.id) {
        FxJson.dataUrlBytes(pic.image)?.let { b -> runCatching { BitmapFactory.decodeByteArray(b, 0, b.size) }.getOrNull() }
    }
    if (bmp != null) {
        Spacer(Modifier.height(8.dp))
        Image(bmp.asImageBitmap(), contentDescription = null, modifier = Modifier.height(100.dp))
    }
    var text by remember(pic.id) { mutableStateOf("") }
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = text, onValueChange = { text = it }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(R.string.fx_renew_field)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text)
    )
    if (pic.notice.isNotEmpty()) {
        Spacer(Modifier.height(4.dp))
        Text(stringResource(R.string.fx_renew_send_failed, pic.notice), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    }
    Spacer(Modifier.height(8.dp))
    Button(enabled = text.isNotBlank(), onClick = { onSend(pic.id, text.trim()) }) { Text(stringResource(R.string.fx_renew_send)) }
}

@Composable
private fun failureText(f: FxRenewUi.Failed): String = when (f.code) {
    "too_many_captchas" -> stringResource(R.string.fx_renew_err_too_many_captchas)
    "refresh_still_challenged" -> stringResource(R.string.fx_renew_err_refresh_still_challenged)
    "persist_failed" -> stringResource(R.string.fx_renew_err_persist_failed)
    "sign_in_required" -> stringResource(R.string.fx_renew_err_sign_in_required)
    "answer_rejected" -> stringResource(R.string.fx_renew_err_answer_rejected)
    "post_back_failed" -> stringResource(R.string.fx_renew_err_post_back_failed)
    "challenge_not_accepted" -> stringResource(R.string.fx_renew_err_challenge_not_accepted)
    "session_cookies_missing" -> stringResource(R.string.fx_renew_err_session_cookies_missing)
    "challenge_rounds_exceeded" -> stringResource(R.string.fx_renew_err_challenge_rounds_exceeded)
    "refresh_failed" -> stringResource(R.string.fx_renew_err_refresh_failed)
    "challenge_failed" -> stringResource(R.string.fx_renew_err_challenge_failed)
    "network" -> stringResource(R.string.fx_renew_err_network)
    "timeout" -> stringResource(R.string.fx_renew_err_timeout)
    FxReauthCodes.BUSY -> stringResource(R.string.fx_renew_err_busy)
    FxRenewFlow.SUPERSEDED -> stringResource(R.string.fx_renew_err_superseded)
    FxRenewFlow.LOST -> stringResource(R.string.fx_renew_err_lost)
    FxRenewFlow.REQUEST -> stringResource(R.string.fx_renew_err_request_failed, f.detail.ifEmpty { "?" })
    else -> stringResource(R.string.fx_renew_failed, f.detail.ifEmpty { f.code })
}
