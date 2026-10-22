package com.aethershield.app.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
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
     * False while the phone has no default network at all (data off, airplane mode, Wi-Fi gone). True at the
     * start and whenever the callback could not be registered, so a failure here never pauses anything.
     */
    val online: Boolean get() = tracker.online

    @Synchronized
    fun start() {
        if (callback != null) return
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (tracker.available(network)) { // a new network, or the link coming back after "no network"
                    changes.trySend(Unit)
                    onChanged?.invoke()
                }
            }

            override fun onLost(network: Network) {
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
