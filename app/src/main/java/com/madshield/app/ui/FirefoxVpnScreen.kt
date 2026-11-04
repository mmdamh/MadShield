package com.madshield.app.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.*
import com.madshield.app.ui.components.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The Firefox VPN page: sign in with a Firefox Account, see the data left, choose a location.
 *
 * It talks to the core's loopback API through [FxClient]. If a connection runs the Firefox engine, that engine's core is
 * used; otherwise this page starts a core of its own ([FxSession]) and stops it when the page closes, so nothing keeps
 * running for an account page. While the page is in the foreground it asks for the status every few seconds (every
 * 1.5 s only during a sign-in that is waiting for Mozilla); in the background it asks for nothing.
 */
@Composable
fun FirefoxVpnScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val foreground by rememberIsForeground()

    var loading by remember { mutableStateOf(true) }
    var fatal by remember { mutableStateOf<String?>(null) }
    var accounts by remember { mutableStateOf<List<FxAccount>>(emptyList()) }
    var status by remember { mutableStateOf<FxStatus?>(null) }
    var locations by remember { mutableStateOf<List<FxLocation>?>(null) }
    var signIn by remember { mutableStateOf<FxSignIn?>(null) }
    var signInError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }
    var reload by remember { mutableIntStateOf(0) }
    val inBuild = remember { FxRuntime.isInBuild(ctx) }

    /** One pass of reading: status and accounts, and the locations once an account exists. */
    suspend fun refresh(withLocations: Boolean) {
        withContext(Dispatchers.IO) {
            val ep = FxSession.ensure(ctx)
            FxSession.awaitApi(ep, FxVpn.START_ALLOWANCE_MS)
            val c = ep.client()
            val acc = c.accounts()
            val st = c.status()
            val locs = if (acc.isNotEmpty() && (withLocations || locations == null)) runCatching { c.locations() }.getOrNull() else null
            withContext(Dispatchers.Main) {
                accounts = acc
                status = st
                if (acc.isEmpty()) locations = null else if (locs != null) locations = locs
            }
        }
    }

    // The core of this page stops when the page closes (a connection's own core is never touched by this).
    DisposableEffect(Unit) { onDispose { FxSession.release() } }

    LaunchedEffect(reload) {
        if (!inBuild) { loading = false; return@LaunchedEffect }
        loading = true; fatal = null
        try {
            refresh(withLocations = true)
        } catch (e: Exception) {
            fatal = e.message ?: e.javaClass.simpleName
        } finally {
            loading = false
        }
    }

    // Light polling, foreground only: sign-in progress quickly, the rest slowly.
    val polling = inBuild && !loading && fatal == null && foreground
    LaunchedEffect(polling, signIn?.id, signIn?.step) {
        if (!polling) return@LaunchedEffect
        while (true) {
            val si = signIn
            val waitingOnMozilla = si != null && !si.step.finished && !si.step.needsInput
            delay(if (waitingOnMozilla) 1_500L else 6_000L)
            try {
                if (si != null && !si.step.finished) {
                    val next = withContext(Dispatchers.IO) { FxSession.ensure(ctx).client().signInGet(si.id) }
                    signIn = next
                    if (next.step == FxStep.DONE) { signIn = null; refresh(withLocations = true) }
                } else {
                    refresh(withLocations = false)
                }
            } catch (_: Exception) {
                // the core may be restarting (a connection started); the next round asks again
            }
        }
    }

    fun launchCall(block: suspend (FxClient) -> Unit) {
        scope.launch {
            busy = true
            try {
                withContext(Dispatchers.IO) { block(FxSession.ensure(ctx).client()) }
            } catch (e: Exception) {
                signInError = e.message ?: e.javaClass.simpleName
            } finally {
                busy = false
            }
        }
    }

    Scaffold(topBar = { BackTopBar(stringResource(R.string.fx_title), onBack) }) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            InfoHint(stringResource(R.string.fx_intro))
            InfoHint(stringResource(R.string.fx_privacy))

            when {
                !inBuild -> HelperText(stringResource(R.string.fx_engine_missing), error = true)
                loading -> Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.fx_starting), style = MaterialTheme.typography.bodyMedium)
                }
                fatal != null -> SectionCard(stringResource(R.string.fx_title)) {
                    HelperText(stringResource(R.string.fx_start_failed, fatal ?: ""), error = true)
                    Spacer(Modifier.height(8.dp))
                    FilledTonalButton(onClick = { reload++ }) { Text(stringResource(R.string.fx_retry)) }
                }
                else -> {
                    val account = accounts.firstOrNull() // one account only: the app never adds or switches between accounts
                    val si = signIn
                    if (account == null) {
                        SignInCard(
                            signIn = si, error = signInError, busy = busy,
                            onStart = { email, password ->
                                signInError = null
                                scope.launch {
                                    busy = true
                                    try { signIn = withContext(Dispatchers.IO) { FxSession.ensure(ctx).client().signInStart(email.trim(), password) } }
                                    catch (e: Exception) { signInError = e.message ?: e.javaClass.simpleName }
                                    finally { busy = false }
                                }
                            },
                            onAnswer = { value ->
                                val id = si?.id ?: return@SignInCard
                                signInError = null
                                scope.launch {
                                    busy = true
                                    try { signIn = withContext(Dispatchers.IO) { FxSession.ensure(ctx).client().signInAnswer(id, value.trim()) } }
                                    catch (e: Exception) { signInError = e.message ?: e.javaClass.simpleName }
                                    finally { busy = false }
                                }
                            },
                            onCancel = {
                                val id = si?.id
                                signIn = null; signInError = null
                                if (id != null) launchCall { it.signInCancel(id) }
                            }
                        )
                    } else {
                        AccountCard(account, status, onRemove = { confirmRemove = true })
                        LocationCard(
                            locations = locations,
                            selected = status?.selection ?: "",
                            busy = busy,
                            onPick = { code ->
                                launchCall { it.setLocation(code) }
                                // show the choice at once; the next status read confirms it
                                status = status?.copy(selection = code)
                            }
                        )
                        status?.takeIf { it.exitCountry.isNotEmpty() }?.let {
                            HelperText(stringResource(R.string.fx_exit_now, listOf(it.exitCity, it.exitCountry).filter { s -> s.isNotEmpty() }.joinToString(", ")))
                        }
                        if (FxRuntime.endpoint != null && !FxSession.ownsCore) HelperText(stringResource(R.string.fx_vpn_running_note))
                    }
                }
            }
            Spacer(Modifier.height(NavClearance))
        }
    }

    if (confirmRemove) {
        val id = accounts.firstOrNull()?.id
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            title = { Text(stringResource(R.string.fx_remove_title)) },
            text = { Text(stringResource(R.string.fx_remove_text)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmRemove = false
                    if (id != null) {
                        scope.launch {
                            busy = true
                            try {
                                withContext(Dispatchers.IO) { FxSession.ensure(ctx).client().removeAccount(id) }
                                refresh(withLocations = true)
                            } catch (e: Exception) {
                                signInError = e.message ?: e.javaClass.simpleName
                            } finally { busy = false }
                        }
                    }
                }) { Text(stringResource(R.string.fx_remove)) }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text(stringResource(R.string.action_cancel)) } }
        )
    }
}

// ------------------------------------------------------------------------------------------------ sign-in

@Composable
private fun SignInCard(
    signIn: FxSignIn?,
    error: String?,
    busy: Boolean,
    onStart: (String, String) -> Unit,
    onAnswer: (String) -> Unit,
    onCancel: () -> Unit
) {
    SectionCard(stringResource(R.string.fx_signin_title)) {
        val step = signIn?.step
        if (signIn == null || step == FxStep.FAILED || step == FxStep.CANCELLED) {
            var email by remember { mutableStateOf("") }
            var password by remember { mutableStateOf("") }
            OutlinedTextField(
                value = email, onValueChange = { email = it }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.fx_email)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email)
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = password, onValueChange = { password = it }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.fx_password)) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
            )
            (signIn?.takeIf { it.step == FxStep.FAILED }?.let { it.error.ifEmpty { it.message } } ?: error)?.let {
                HelperText(stringResource(R.string.fx_signin_failed, it), error = true)
            }
            Spacer(Modifier.height(10.dp))
            Button(
                enabled = !busy && email.contains('@') && password.isNotEmpty(),
                onClick = { val p = password; password = ""; onStart(email, p) }
            ) { Text(stringResource(R.string.fx_signin)) }
        } else {
            val info = when (step) {
                FxStep.EMAIL_CODE -> R.string.fx_step_email_code
                FxStep.TOTP -> R.string.fx_step_totp
                FxStep.UNBLOCK_CODE -> R.string.fx_step_unblock
                FxStep.CAPTCHA -> R.string.fx_step_captcha
                FxStep.EMAIL_LINK -> R.string.fx_step_link
                else -> R.string.fx_step_working
            }
            Text(stringResource(info), style = MaterialTheme.typography.bodyMedium)
            if (step == FxStep.CAPTCHA) {
                val bmp = remember(signIn.captcha) {
                    FxJson.dataUrlBytes(signIn.captcha)?.let { b -> runCatching { BitmapFactory.decodeByteArray(b, 0, b.size) }.getOrNull() }
                }
                if (bmp != null) {
                    Spacer(Modifier.height(8.dp))
                    Image(bmp.asImageBitmap(), contentDescription = null, modifier = Modifier.height(100.dp))
                }
            }
            if (step != null && step.needsInput) {
                var code by remember(signIn.id, step) { mutableStateOf("") }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = code, onValueChange = { code = it }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.fx_code)) },
                    keyboardOptions = KeyboardOptions(keyboardType = if (step == FxStep.CAPTCHA) KeyboardType.Text else KeyboardType.Number)
                )
                if (signIn.error.isNotEmpty()) HelperText(signIn.error, error = true)
                Spacer(Modifier.height(10.dp))
                Button(enabled = !busy && code.isNotBlank(), onClick = { onAnswer(code) }) { Text(stringResource(R.string.fx_continue)) }
            } else {
                Spacer(Modifier.height(10.dp))
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }
            error?.let { HelperText(it, error = true) }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onCancel) { Text(stringResource(R.string.action_cancel)) }
        }
    }
}

// ------------------------------------------------------------------------------------------------ account

@Composable
private fun AccountCard(account: FxAccount, status: FxStatus?, onRemove: () -> Unit) {
    SectionCard(stringResource(R.string.fx_account)) {
        Text(stringResource(R.string.fx_signed_in_as, account.email), style = MaterialTheme.typography.titleSmall)
        if (account.status.isNotEmpty()) HelperText(stringResource(R.string.fx_account_status, account.status))
        Spacer(Modifier.height(12.dp))
        Text(stringResource(R.string.fx_quota), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(6.dp))
        when {
            account.unlimited -> Text(stringResource(R.string.fx_quota_unlimited), style = MaterialTheme.typography.bodyMedium)
            account.limitBytes > 0 -> {
                LinearProgressIndicator(
                    progress = { (account.usedBytes.toFloat() / account.limitBytes.toFloat()).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.fx_quota_used, fmtBytes(account.usedBytes), fmtBytes(account.limitBytes)),
                    style = MaterialTheme.typography.bodyMedium
                )
                if (account.resetAt.length >= 10) HelperText(stringResource(R.string.fx_quota_resets, account.resetAt.take(10)))
            }
            else -> HelperText(stringResource(R.string.fx_quota_unknown))
        }
        status?.let {
            if (it.downBytes + it.upBytes > 0) {
                HelperText("↓ ${fmtBytes(it.downBytes)}   ↑ ${fmtBytes(it.upBytes)}")
            }
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onRemove) { Text(stringResource(R.string.fx_remove), color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
private fun LocationCard(locations: List<FxLocation>?, selected: String, busy: Boolean, onPick: (String) -> Unit) {
    SectionCard(stringResource(R.string.fx_location)) {
        when {
            locations == null -> HelperText(stringResource(R.string.fx_location_loading))
            locations.isEmpty() -> HelperText(stringResource(R.string.fx_location_none))
            else -> {
                locations.forEach { l ->
                    // "" (or the recommended entry) is the core's own choice
                    val isSel = if (selected.isEmpty()) l.recommended else selected.equals(l.code, ignoreCase = true)
                    Row(
                        Modifier.fillMaxWidth().clickable(enabled = !busy) { onPick(if (l.recommended) "" else l.code) }.padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(selected = isSel, onClick = null)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(l.name + if (l.city.isNotEmpty()) " · ${l.city}" else "", style = MaterialTheme.typography.bodyLarge)
                            if (l.recommended) Text(stringResource(R.string.fx_location_recommended), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                        }
                        if (l.pingMs > 0) Text("${l.pingMs} ms", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                HelperText(stringResource(R.string.fx_location_note))
            }
        }
    }
}

private fun fmtBytes(b: Long): String = when {
    b >= 1L shl 30 -> String.format(java.util.Locale.US, "%.1f GB", b / (1024.0 * 1024.0 * 1024.0))
    b >= 1L shl 20 -> String.format(java.util.Locale.US, "%.0f MB", b / (1024.0 * 1024.0))
    else -> String.format(java.util.Locale.US, "%d KB", b / 1024)
}
