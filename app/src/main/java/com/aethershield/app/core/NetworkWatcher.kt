package com.aethershield.app.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Tells the reconnect logic when the phone's own network changed (Wi-Fi to mobile, link back after an outage),
 * so a long wait can be cut short instead of sleeping through the moment the internet came back. It also knows
 * whether there is any network at all ([online]), so the services can stop the engine instead of letting it
 * spin while nothing is reachable (see [OnlineTracker]).
 *
 * Registered only while a service runs. Our app is kept outside its own VPN, so this reports the real
 * underlying network, not the tunnel. Events are conflated into one pending flag: a burst of callbacks wakes
 * the waiter once, and nothing runs while nobody is waiting.
 */
class NetworkWatcher(private val context: Context) {
    private val changes = Channel<Unit>(Channel.CONFLATED)
    private var callback: ConnectivityManager.NetworkCallback? = null
    private val tracker = OnlineTracker<Network>()

    /** Called (from a system thread) whenever a new network shows up; lets other loops cut a long sleep short. */
    @Volatile var onChanged: (() -> Unit)? = null

    /** Called (from a system thread) when the phone loses its last network; lets the health loop notice at once. */
    @Volatile var onOffline: (() -> Unit)? = null

    /**
     * The system's current default (real, non-tunnel) network, or null when there is none. Our app is kept outside
     * its own VPN, so this is the network the tunnel's traffic really leaves on.
     */
    @Volatile var currentDefault: Network? = null
        private set

    /**
     * Called (from a system thread) whenever [currentDefault] changes (null = no network left). The VPN service uses
     * it to tell Android which network carries the tunnel (VpnService.setUnderlyingNetworks), so the system's
     * traffic accounting does not count the same bytes again. Event-driven: no timer, no extra callback.
     */
    @Volatile var onDefaultNetwork: ((Network?) -> Unit)? = null

    /**
     * False while the phone has no default network at all (data off, airplane mode, Wi-Fi gone). True at the
     * start and whenever the callback could not be registered, so a failure here never pauses anything.
     */
    val online: Boolean get() = tracker.online

    /**
     * A direct look at the system, independent of the callbacks: is there any network that is not our own tunnel
     * and claims Internet access? (Not "validated": on filtered networks the system's own check often fails while
     * the link is fine.) True whenever it cannot tell, so a failure here never pauses anything.
     */
    @Suppress("DEPRECATION")
    fun hasRealNetwork(): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return true
        return try {
            cm.allNetworks.any { n ->
                val caps = cm.getNetworkCapabilities(n)
                caps != null &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
        } catch (_: Throwable) {
            true
        }
    }

    /**
     * True when there is no usable network: the callbacks said so, or the direct look finds none. The second part
     * matters on phones where the loss is never reported (the engine then spun on "Network is unreachable").
     */
    fun isOffline(): Boolean = !tracker.online || !hasRealNetwork()

    /**
     * Suspends until [hasRealNetwork]. The system callback wakes it at once; [pollMs] is only the safety net for a
     * callback that never comes. It is asked again before every wait, so the interval can follow the screen state.
     */
    suspend fun awaitNetwork(pollMs: () -> Long) {
        while (!hasRealNetwork()) awaitChangeOrTimeout(pollMs())
        tracker.markOnline()
    }

    @Synchronized
    fun start() {
        if (callback != null) return
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                currentDefault = network
                onDefaultNetwork?.invoke(network)
                if (tracker.available(network)) { // a new network, or the link coming back after "no network"
                    changes.trySend(Unit)
                    onChanged?.invoke()
                }
            }

            override fun onLost(network: Network) {
                // On a Wi-Fi/mobile switch the system reports the new network first and the old one lost afterwards:
                // only clear when the lost network is still the one we hold.
                if (currentDefault == network) {
                    currentDefault = null
                    onDefaultNetwork?.invoke(null)
                }
                if (tracker.lost(network)) onOffline?.invoke()
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            callback = cb
        } catch (_: Throwable) {
            // No callback: waits simply run their full length.
        }
    }

    @Synchronized
    fun stop() {
        val cb = callback ?: return
        callback = null
        currentDefault = null
        runCatching { context.getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) }
    }

    /** Forget changes that happened before now. */
    fun drain() {
        while (changes.tryReceive().isSuccess) { /* discard */ }
    }

    /** @return true if the network changed within [timeoutMs], false if the whole time passed. */
    suspend fun awaitChangeOrTimeout(timeoutMs: Long): Boolean =
        withTimeoutOrNull(timeoutMs) { changes.receive() } != null

    /** Suspends until a network is there (returns at once when one is). No timer: it is woken by the system callback. */
    suspend fun awaitOnline() {
        while (!tracker.online) changes.receive()
    }
}
