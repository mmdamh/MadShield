package com.madshield.app.core

import java.io.File

/** How the app's own storage splits up. Bytes. */
data class StorageReport(val rules: Long, val engine: Long, val cache: Long, val settings: Long) {
    val total: Long get() = rules + engine + cache + settings
}

/**
 * What the cleaner may remove. [maxAgeDays] is how old a leftover must be (0 = every leftover of the cache).
 * [keepEngineData]: the engines' own data (Psiphon, Tor) is kept for a faster connect and only trimmed once it
 * grows past [StorageCleaner.ENGINE_CAP_BYTES]; off, anything older than [maxAgeDays] goes.
 */
data class CleanPolicy(val maxAgeDays: Int = 14, val keepEngineData: Boolean = true)

/** The Storage page's settings. [lastCleanMs] is when the automatic clean-up last ran (epoch ms, 0 = never). */
data class StoragePrefs(
    val autoClean: Boolean = true,
    val maxAgeDays: Int = 14,
    val keepEngineData: Boolean = true,
    val lastCleanMs: Long = 0L
) {
    fun policy() = CleanPolicy(maxAgeDays, keepEngineData)

    /** The automatic clean-up runs at most once a day. */
    fun autoDue(nowMs: Long): Boolean = autoClean && nowMs - lastCleanMs >= 24L * 60 * 60 * 1000

    companion object {
        val CHOICES = listOf(7, 14, 30)
        fun normalizeDays(d: Int?): Int = if (d != null && d in CHOICES) d else 14
    }
}

/**
 * Removes leftovers from the app's own folders. It runs only when nothing is connected (the caller checks), never
 * by itself on a timer, and it never touches: the WARP identity (`aether.toml`), the rule lists, the settings, the
 * usage totals, or anything newer than the age asked for.
 *
 *  - cache folder: every file older than the age (age 0: all of it), then folders left empty;
 *  - `*.tmp` files beside the rule lists and settings: only when more than an hour old (a write may be running);
 *  - engine data (`psiphon`, `tor`): see [CleanPolicy.keepEngineData].
 *
 * Plain java.io, so it is tested off-device.
 */
object StorageCleaner {
    const val ENGINE_CAP_BYTES = 50L * 1024 * 1024
    private const val DAY_MS = 24L * 60 * 60 * 1000
    private const val TMP_MIN_AGE_MS = 60L * 60 * 1000
    private val ENGINE_DIRS = listOf("psiphon", "tor")

    fun dirSize(f: File): Long {
        if (f.isFile) return f.length()
        val kids = f.listFiles() ?: return 0
        var n = 0L
        for (k in kids) n += dirSize(k)
        return n
    }

    /** [dataDir] is the app's private data folder (its parent holds `shared_prefs`); null = unknown. */
    fun report(filesDir: File, cacheDir: File, dataDir: File?): StorageReport {
        val rules = dirSize(File(filesDir, "rules")) + dirSize(File(filesDir, "routes.txt")) + dirSize(File(filesDir, "routes.sig"))
        var engine = dirSize(File(filesDir, "aether.toml"))
        for (d in ENGINE_DIRS) engine += dirSize(File(filesDir, d))
        val cache = dirSize(cacheDir)
        val settings = dirSize(File(filesDir, "datastore")) + dirSize(File(filesDir, UsageFile.NAME)) +
            (dataDir?.let { dirSize(File(it, "shared_prefs")) } ?: 0L)
        return StorageReport(rules, engine, cache, settings)
    }

    /** What [clean] would free right now, without removing anything. */
    fun reclaimable(filesDir: File, cacheDir: File, policy: CleanPolicy, nowMs: Long): Long =
        run(filesDir, cacheDir, policy, nowMs, dryRun = true)

    /** @return the bytes freed. */
    fun clean(filesDir: File, cacheDir: File, policy: CleanPolicy, nowMs: Long): Long =
        run(filesDir, cacheDir, policy, nowMs, dryRun = false)

    private fun run(filesDir: File, cacheDir: File, policy: CleanPolicy, nowMs: Long, dryRun: Boolean): Long {
        val cutoff = nowMs - policy.maxAgeDays.coerceAtLeast(0) * DAY_MS
        var freed = 0L

        // 1. the cache folder
        freed += sweep(cacheDir, cutoff, dryRun, removeEmptyDirs = true)

        // 2. half-written temp files
        val tmpCutoff = nowMs - TMP_MIN_AGE_MS
        for (dir in listOf(filesDir, File(filesDir, "rules"))) {
            val kids = dir.listFiles() ?: continue
            for (k in kids) {
                if (k.isFile && k.name.endsWith(".tmp") && k.lastModified() < tmpCutoff) freed += removeFile(k, dryRun)
            }
        }

        // 3. engine data
        if (policy.keepEngineData) {
            var size = 0L
            for (d in ENGINE_DIRS) size += dirSize(File(filesDir, d))
            if (size > ENGINE_CAP_BYTES) {
                // oldest first, only files that are past the age, until it is under the cap
                val old = ArrayList<File>()
                for (d in ENGINE_DIRS) collectOlderThan(File(filesDir, d), cutoff, old)
                old.sortBy { it.lastModified() }
                for (f in old) {
                    if (size <= ENGINE_CAP_BYTES) break
                    val n = f.length()
                    freed += removeFile(f, dryRun)
                    size -= n
                }
            }
        } else {
            for (d in ENGINE_DIRS) freed += sweep(File(filesDir, d), cutoff, dryRun, removeEmptyDirs = false)
        }
        return freed
    }

    private fun collectOlderThan(dir: File, cutoff: Long, out: MutableList<File>) {
        val kids = dir.listFiles() ?: return
        for (k in kids) {
            if (k.isDirectory) collectOlderThan(k, cutoff, out)
            else if (k.lastModified() < cutoff) out.add(k)
        }
    }

    private fun sweep(dir: File, cutoff: Long, dryRun: Boolean, removeEmptyDirs: Boolean): Long {
        val kids = dir.listFiles() ?: return 0
        var freed = 0L
        for (k in kids) {
            if (k.isDirectory) {
                freed += sweep(k, cutoff, dryRun, removeEmptyDirs)
                if (removeEmptyDirs && !dryRun && (k.listFiles()?.isEmpty() == true)) k.delete()
            } else if (k.lastModified() < cutoff) {
                freed += removeFile(k, dryRun)
            }
        }
        return freed
    }

    private fun removeFile(f: File, dryRun: Boolean): Long {
        val n = f.length()
        return if (dryRun || f.delete()) n else 0L
    }
}
