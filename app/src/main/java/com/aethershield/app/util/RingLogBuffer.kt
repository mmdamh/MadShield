package com.aethershield.app.util

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.ArrayDeque

/**
 * Zero-log design, spelled out:
 *
 * - This buffer lives ONLY in process memory (a plain ArrayDeque). It is never
 *   written to a file, never written to SharedPreferences/DataStore, and never
 *   sent anywhere over the network -- there is no analytics or crash-reporting
 *   SDK in this app to send it to in the first place (check app/build.gradle.kts,
 *   the dependency list is short and everything in it is inspectable).
 * - It is capped at [capacity] lines; once full, the oldest line is dropped.
 * - It is cleared explicitly on every VPN/engine stop (see AetherVpnService.onDestroy)
 *   and implicitly on process death, since nothing here is persisted.
 * - android.util.Log calls are stripped from release builds entirely via the
 *   ProGuard rule in proguard-rules.pro, as a second, independent layer -- so even
 *   if a future contributor adds a stray Log.d(), it will not compile into a
 *   release APK.
 *
 * Honest limitation: this controls what THIS APP does. It cannot control
 * whether the Android OS itself writes low-level system log lines (e.g. "VPN
 * connected" via ConnectivityManager) to the system logcat -- that is OS
 * behavior outside any app's reach, on stock Android. If you need to verify
 * that, `adb logcat` on your own device is the way to check it, not this app.
 */
object RingLogBuffer {
    private const val CAPACITY = 500
    private val buffer = ArrayDeque<String>(CAPACITY)
    private val _lines = MutableStateFlow<List<String>>(emptyList())
    val lines = _lines.asStateFlow()

    @Synchronized
    fun append(line: String) {
        if (buffer.size >= CAPACITY) buffer.removeFirst()
        buffer.addLast(line)
        _lines.value = buffer.toList()
    }

    @Synchronized
    fun clear() {
        buffer.clear()
        _lines.value = emptyList()
    }
}
