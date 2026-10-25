package com.aethershield.app.ui

import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aethershield.app.R
import com.aethershield.app.core.AetherController
import com.aethershield.app.core.ConnectionState
import com.aethershield.app.core.LinkAdd
import com.aethershield.app.core.LinkError
import com.aethershield.app.core.LinkParse
import com.aethershield.app.core.LinkProfile
import com.aethershield.app.core.LinkProfileBook
import com.aethershield.app.core.LinkProfiles
import com.aethershield.app.core.LinkSwapState
import com.aethershield.app.core.ProxyLink
import com.aethershield.app.core.SettingsStore
import com.aethershield.app.ui.components.CookieBadge
import com.aethershield.app.ui.components.HelperText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The saved links of the custom chain (update17): a short list you can switch between with one tap, instead of one
 * text box that had to be overwritten each time.
 *
 * Tap a link = it becomes the one the chain uses. While connected that happens LIVE (update18): only the sing-box part
 * is replaced, the WARP tunnel stays up (see ChainLinkSwapper); when disconnected it is used on the next connect. Each link is
 * checked by the same parser as before before it can be saved, so nothing is stored that the app could not turn into a
 * sing-box configuration. The links hold a UUID or a password: they live only in the Keystore-backed store
 * ([SettingsStore.saveLinkBook]), the page shows only a name and a credential-free summary, and the field where you
 * paste one is masked unless you ask to see it.
 *
 * The engine still reads a single link; [SettingsStore.saveLinkBook] keeps that one equal to the active link.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomLinkEditor() {
    val ctx = LocalContext.current
    val appContext = ctx.applicationContext
    val store = remember { SettingsStore(appContext) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val lock = remember { Mutex() }

    var loaded by remember { mutableStateOf(false) }
    var book by remember { mutableStateOf(LinkProfileBook()) }
    var storeFailed by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var adding by rememberSaveable { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<LinkProfile?>(null) }
    var deleting by remember { mutableStateOf<LinkProfile?>(null) }
    val swap by AetherController.linkSwap.collectAsState()
    val connected = AetherController.state.collectAsState().value is ConnectionState.Connected

    LaunchedEffect(Unit) {
        book = withContext(Dispatchers.IO) { store.loadLinkBook() }
        loaded = true
    }
    // The service puts the saved choice back to the working link when a switch fails: show what is really saved.
    LaunchedEffect(swap) {
        when (swap) {
            is LinkSwapState.Failed -> book = withContext(Dispatchers.IO) { store.loadLinkBook() }
            is LinkSwapState.Done -> { delay(4_000); if (AetherController.linkSwap.value is LinkSwapState.Done) AetherController.setLinkSwap(LinkSwapState.Idle) }
            else -> Unit
        }
    }

    /** One change at a time: each is computed from the latest saved book and only shown once it really was saved. */
    fun commit(switchLive: Boolean = false, transform: (LinkProfileBook) -> LinkProfileBook) {
        scope.launch {
            lock.withLock {
                val next = transform(book)
                if (next != book) {
                    val ok = withContext(Dispatchers.IO) { store.saveLinkBook(next) }
                    if (ok) {
                        book = next; storeFailed = false
                        // Saved first, then asked: the running service reads the saved link itself (nothing secret is passed on).
                        if (switchLive && next.activeId != null) AetherController.requestLinkSwap()
                    } else { storeFailed = true }
                }
            }
        }
    }

    fun addLink(raw: String, name: String) {
        scope.launch {
            lock.withLock {
                when (val r = LinkProfiles.add(book, raw, name)) {
                    is LinkAdd.Added -> {
                        val ok = withContext(Dispatchers.IO) { store.saveLinkBook(r.book) }
                        if (ok) { book = r.book; storeFailed = false; message = null } else { storeFailed = true }
                    }
                    is LinkAdd.Duplicate -> { message = ctx.getString(R.string.link_dup, r.existing.name) }
                    LinkAdd.Full -> { message = ctx.getString(R.string.link_full, LinkProfiles.MAX_PROFILES) }
                    is LinkAdd.Invalid -> { message = linkErrorText(ctx, r.error) }
                }
            }
        }
    }

    Column(Modifier.fillMaxWidth()) {
        if (!loaded) {
            Spacer(Modifier.height(72.dp))
        } else if (book.profiles.isEmpty()) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                CookieBadge(56.dp) { Icon(Icons.Rounded.Link, null, tint = MaterialTheme.colorScheme.onPrimaryContainer) }
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.link_title), style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                    Text(stringResource(R.string.link_empty), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        } else {
            Row(Modifier.fillMaxWidth().padding(bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(R.string.link_title), style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.weight(1f)
                )
                Text(
                    stringResource(R.string.link_count, book.profiles.size),
                    style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                book.profiles.forEach { p ->
                    LinkRow(
                        profile = p,
                        active = p.id == book.activeId,
                        onUse = { commit(switchLive = true) { LinkProfiles.activate(it, p.id) } },
                        onRename = { renaming = p },
                        onDelete = { deleting = p }
                    )
                }
            }
        }

        if (loaded) {
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(
                    onClick = {
                        val text = clipboard.getText()?.text?.trim().orEmpty()
                        if (text.isEmpty()) message = ctx.getString(R.string.link_clipboard_empty) else addLink(text, "")
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.ContentPaste, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.link_paste_add), maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                OutlinedButton(onClick = { adding = true; message = null }, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Rounded.Add, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.link_add), maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            when {
                storeFailed -> HelperText(stringResource(R.string.link_keystore_fail), error = true)
                message != null -> HelperText(message.orEmpty(), error = true)
                book.profiles.isEmpty() -> HelperText(stringResource(R.string.link_need), error = true)
                book.active == null -> HelperText(stringResource(R.string.link_pick), error = true)
            }
            when (val sw = swap) {
                LinkSwapState.Swapping -> {
                    Spacer(Modifier.height(8.dp))
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    HelperText(stringResource(R.string.link_swapping))
                }
                is LinkSwapState.Done -> HelperText(stringResource(R.string.link_swapped))
                is LinkSwapState.Failed -> HelperText(
                    stringResource(if (sw.restored) R.string.link_swap_failed_restored else R.string.link_swap_failed, sw.reason.take(160)),
                    error = true
                )
                LinkSwapState.Idle -> if (connected && book.active != null && !storeFailed && message == null) {
                    HelperText(stringResource(R.string.link_live_hint))
                }
            }
        }
    }

    if (adding) {
        ModalBottomSheet(
            onDismissRequest = { adding = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            AddLinkSheet(
                book = book,
                onPasteText = { clipboard.getText()?.text?.trim().orEmpty() },
                onSave = { link, name -> adding = false; addLink(link, name) }
            )
        }
    }

    renaming?.let { target ->
        var text by remember(target.id) { mutableStateOf(target.name) }
        AlertDialog(
            onDismissRequest = { renaming = null },
            title = { Text(stringResource(R.string.link_rename)) },
            text = {
                OutlinedTextField(
                    value = text, onValueChange = { text = it.take(LinkProfiles.MAX_NAME) },
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                TextButton(
                    enabled = LinkProfiles.cleanName(text).isNotEmpty(),
                    onClick = { commit { LinkProfiles.rename(it, target.id, text) }; renaming = null }
                ) { Text(stringResource(R.string.action_save)) }
            },
            dismissButton = { TextButton(onClick = { renaming = null }) { Text(stringResource(R.string.action_cancel)) } }
        )
    }

    deleting?.let { target ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text(stringResource(R.string.link_delete_title, target.name)) },
            text = { Text(stringResource(R.string.link_delete_body)) },
            confirmButton = {
                TextButton(onClick = { commit { LinkProfiles.remove(it, target.id) }; deleting = null }) {
                    Text(stringResource(R.string.link_remove), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text(stringResource(R.string.action_cancel)) } }
        )
    }
}

/** One saved link: a tap uses it. Shows the name and a credential-free summary, never the link itself. */
@Composable
private fun LinkRow(
    profile: LinkProfile,
    active: Boolean,
    onUse: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit
) {
    val cs = MaterialTheme.colorScheme
    val parsed = remember(profile.link) { ProxyLink.parse(profile.link) }
    var menu by remember { mutableStateOf(false) }
    Surface(
        onClick = onUse,
        shape = RoundedCornerShape(22.dp),
        color = if (active) cs.primaryContainer else cs.surfaceContainerHigh,
        border = if (active) BorderStroke(1.5.dp, cs.primary) else null,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(Modifier.padding(start = 12.dp, top = 8.dp, bottom = 8.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            if (active) {
                CookieBadge(44.dp) { Icon(Icons.Rounded.Check, null, tint = cs.onPrimaryContainer, modifier = Modifier.size(22.dp)) }
            } else {
                Box(Modifier.size(44.dp), contentAlignment = Alignment.Center) {
                    Icon(Icons.Rounded.Link, null, tint = cs.onSurfaceVariant, modifier = Modifier.size(22.dp))
                }
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    profile.name, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    color = if (active) cs.onPrimaryContainer else cs.onSurface
                )
                Text(
                    when (parsed) {
                        is LinkParse.Ok -> ltr(parsed.summary)
                        is LinkParse.Err -> stringResource(R.string.link_unusable)
                    },
                    style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    color = if (parsed is LinkParse.Err) cs.error else if (active) cs.onPrimaryContainer else cs.onSurfaceVariant
                )
            }
            if (active) {
                Text(
                    stringResource(R.string.link_active), style = MaterialTheme.typography.labelMedium,
                    color = cs.onPrimaryContainer, modifier = Modifier.padding(horizontal = 4.dp)
                )
            }
            Box {
                IconButton(onClick = { menu = true }) {
                    Icon(Icons.Rounded.MoreVert, contentDescription = null, tint = if (active) cs.onPrimaryContainer else cs.onSurfaceVariant)
                }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.link_rename)) },
                        leadingIcon = { Icon(Icons.Rounded.Edit, null) },
                        onClick = { menu = false; onRename() }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.link_remove), color = cs.error) },
                        leadingIcon = { Icon(Icons.Rounded.Delete, null, tint = cs.error) },
                        onClick = { menu = false; onDelete() }
                    )
                }
            }
        }
    }
}

/** The "add a link" sheet: paste (or type), see at once whether the app can use it, give it a name if you like. */
@Composable
private fun AddLinkSheet(
    book: LinkProfileBook,
    onPasteText: () -> String,
    onSave: (link: String, name: String) -> Unit
) {
    val ctx = LocalContext.current
    var link by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }

    val parsed = remember(link) { if (link.isBlank()) null else ProxyLink.parse(link) }
    val duplicate = remember(link, book) { book.profiles.firstOrNull { it.link == link.trim() } }
    val full = book.profiles.size >= LinkProfiles.MAX_PROFILES
    val canSave = parsed is LinkParse.Ok && duplicate == null && !full

    Column(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp).padding(bottom = 24.dp).navigationBarsPadding().imePadding(),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(stringResource(R.string.link_add), style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurface)
        OutlinedTextField(
            value = link,
            onValueChange = { link = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text(stringResource(R.string.link_label)) },
            visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
            isError = parsed is LinkParse.Err,
            trailingIcon = {
                TextButton(onClick = { show = !show }) {
                    Text(stringResource(if (show) R.string.link_hide else R.string.link_show))
                }
            }
        )
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { onPasteText().takeIf { it.isNotEmpty() }?.let { link = it } }) {
                Icon(Icons.Rounded.ContentPaste, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.link_paste))
            }
        }
        OutlinedTextField(
            value = name,
            onValueChange = { name = it.take(LinkProfiles.MAX_NAME) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text(stringResource(R.string.link_name)) },
            placeholder = { (parsed as? LinkParse.Ok)?.let { Text(LinkProfiles.defaultName(it)) } }
        )
        when {
            parsed is LinkParse.Err -> HelperText(linkErrorText(ctx, parsed), error = true)
            duplicate != null -> HelperText(stringResource(R.string.link_dup, duplicate.name), error = true)
            full -> HelperText(stringResource(R.string.link_full, LinkProfiles.MAX_PROFILES), error = true)
            parsed is LinkParse.Ok -> HelperText(ltr(parsed.summary))
        }
        // update19: say it when the link turns certificate checking off (it still works as before)
        if (parsed is LinkParse.Ok && ProxyLink.isInsecure(parsed)) HelperText(stringResource(R.string.link_insecure), error = true)
        Spacer(Modifier.height(4.dp))
        Button(onClick = { onSave(link.trim(), name) }, enabled = canSave, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_save))
        }
    }
}

private fun linkErrorText(ctx: Context, e: LinkParse.Err): String {
    val base = ctx.getString(
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
