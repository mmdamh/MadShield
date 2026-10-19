package com.aethershield.app.core

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.PowerManager
import androidx.core.content.ContextCompat
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Knows whether the screen is on WITHOUT polling: one broadcast receiver, registered only while a service
 * runs. It also gives the health loop a sleep that can be cut short ([sleep] / [poke]), so the loop can wait
 * a long time while idle and still react the moment the screen turns on or the network changes.
 * No timers and no wake locks.
 */
class ScreenWatcher(private val context: Context) {
    private val _screenOn = MutableStateFlow(true)
    val screenOn: StateFlow<Boolean> = _screenOn.asStateFlow()
    private val wakes = Channel<Unit>(Channel.CONFLATED)
    private var receiver: BroadcastReceiver? = null

    @Synchronized
    fun start() {
        if (receiver != null) return
        _screenOn.value = runCatching {
            (context.getSystemService(Context.POWER_SERVICE) as PowerManager).isInteractive
        }.getOrDefault(true)
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> { _screenOn.value = true; poke() }
                    Intent.ACTION_SCREEN_OFF -> _screenOn.value = false
                }
            }
        }
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        runCatching {
            ContextCompat.registerReceiver(context, r, f, ContextCompat.RECEIVER_NOT_EXPORTED)
            receiver = r
        }
    }

    @Synchronized
    fun stop() {
        val r = receiver ?: return
        receiver = null
        runCatching { context.unregisterReceiver(r) }
    }

    /** Ends a running [sleep] early (network changed, screen on, ...). */
    fun poke() { wakes.trySend(Unit) }

    /** Forget wake-ups that happened before now. */
    fun drain() { while (wakes.tryReceive().isSuccess) { /* discard */ } }

    /** Waits up to [ms]. @return true when it was woken early, false when the whole time passed. */
    suspend fun sleep(ms: Long): Boolean = withTimeoutOrNull(ms) { wakes.receive() } != null
}
