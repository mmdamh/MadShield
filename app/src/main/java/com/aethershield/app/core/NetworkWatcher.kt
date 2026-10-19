package com.aethershield.app.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Tells the reconnect logic when the phone's own network changed (Wi-Fi to mobile, link back after an outage),
 * so a long wait can be cut short instead of sleeping through the moment the internet came back.
 *
 * Registered only while a service runs. Our app is kept outside its own VPN, so this reports the real
 * underlying network, not the tunnel. Events are conflated into one pending flag: a burst of callbacks wakes
 * the waiter once, and nothing runs while nobody is waiting.
 */
class NetworkWatcher(private val context: Context) {
    private val changes = Channel<Unit>(Channel.CONFLATED)
    private var callback: ConnectivityManager.NetworkCallback? = null

    @Synchronized
    fun start() {
        if (callback != null) return
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            private var current: Network? = null
            override fun onAvailable(network: Network) {
                if (network != current) {
                    current = network // a new network, or the link coming back after "no network"
                    changes.trySend(Unit)
                }
            }

            override fun onLost(network: Network) {
                if (network == current) current = null
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
}
