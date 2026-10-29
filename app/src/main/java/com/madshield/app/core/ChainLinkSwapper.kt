package com.madshield.app.core

import com.madshield.app.util.RingLogBuffer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext

/**
 * Brings the RUNNING custom chain in line with the saved link (update18), without reconnecting.
 *
 * The link editor saves the new active link and calls [AetherController.requestLinkSwap]; the running service (VPN or
 * proxy-only) calls [reconcile] for every request. Because it compares "link in use" with "link saved" instead of
 * carrying the link in the request, a missed or repeated request is harmless, and nothing secret travels through a flow.
 *
 * Only sing-box is replaced (see [EngineProcessManager.swapChainLink]): the core, the WARP tunnel and the TUN bridge keep
 * running. When the new link does not carry traffic, the previous one is started again and the saved choice is put
 * back to it, so what the app shows and what runs never disagree.
 */
class ChainLinkSwapper(private val engine: EngineProcessManager, private val settings: SettingsStore) {

    suspend fun reconcile() {
        try {
            withContext(Dispatchers.IO) { run() }
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            RingLogBuffer.append("[singbox] link switch failed: ${t::class.java.simpleName}: ${t.message}")
            AetherController.setLinkSwap(LinkSwapState.Failed(t.message ?: "error", false, System.currentTimeMillis()))
        }
    }

    private suspend fun run() {
        if (AetherController.state.value !is ConnectionState.Connected || !engine.singboxActive) {
            AetherController.setLinkSwap(LinkSwapState.Idle) // nothing runs: the next connect reads the saved link
            return
        }
        val inUse = engine.chainLinkInUse() ?: return
        // chainLinkFor is null when the profile is no longer "Link": then there is nothing to switch.
        val wanted = settings.chainLinkFor(settings.configFlow.first())?.trim().orEmpty()
        if (wanted.isEmpty() || wanted == inUse) {
            AetherController.setLinkSwap(LinkSwapState.Idle)
            return
        }
        AetherController.setLinkSwap(LinkSwapState.Swapping)
        val out = engine.swapChainLink(wanted)
        val now = System.currentTimeMillis()
        if (out.ok) {
            AetherController.setLinkSwap(LinkSwapState.Done(now))
            return
        }
        // Still on the old link (restored, or never replaced): make the saved choice say so.
        if (engine.chainLinkInUse() == inUse) {
            val book = settings.loadLinkBook()
            val prev = book.profiles.firstOrNull { it.link == inUse }
            if (prev != null) settings.saveLinkBook(LinkProfiles.activate(book, prev.id))
        }
        AetherController.setLinkSwap(LinkSwapState.Failed(out.reason ?: "error", out.restored, now))
    }
}
