package com.madshield.app.core

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext

/**
 * The automatic storage clean-up. It has no timer: it is asked when the app opens and when a connection ends,
 * and it acts only when it is switched on, is due (at most once a day) and nothing is connected.
 */
object StorageAuto {
    suspend fun runIfDue(context: Context, store: SettingsStore) {
        if (AetherController.state.value !is ConnectionState.Idle) return
        val prefs = store.storagePrefsFlow.first()
        val now = System.currentTimeMillis()
        if (!prefs.autoDue(now)) return
        withContext(Dispatchers.IO) {
            StorageCleaner.clean(context.filesDir, context.cacheDir, prefs.policy(), now)
        }
        store.updateStorage { it.copy(lastCleanMs = now) }
    }
}
