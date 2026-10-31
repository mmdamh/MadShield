package com.madshield.app.core

import android.content.Context
import java.util.Locale

/**
 * In-app language. Empty = follow the phone's language (the default, and what the app always did before).
 * Kept in a tiny plain SharedPreferences file, not DataStore, because it has to be read synchronously in
 * attachBaseContext before the first screen exists. Nothing runs in the background for this.
 */
object AppLanguage {
    private const val FILE = "ui_language"
    private const val KEY = "tag"

    const val SYSTEM = ""
    const val FA = "fa"
    const val EN = "en"

    fun get(context: Context): String =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString(KEY, SYSTEM) ?: SYSTEM

    fun set(context: Context, tag: String) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putString(KEY, tag).apply()
    }

    /** Context whose resources use the chosen language; the base context itself when following the phone. */
    fun wrap(base: Context): Context {
        val tag = get(base)
        if (tag == SYSTEM) return base
        val config = android.content.res.Configuration(base.resources.configuration)
        config.setLocale(Locale.forLanguageTag(tag))
        return base.createConfigurationContext(config)
    }
}
