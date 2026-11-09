package com.madshield.app.core

import android.content.Context
import android.net.Uri
import java.io.IOException

/** What restoring did, per part (update41). Counts are items: settings, rules/apps, days, links. */
data class RestoreReport(
    val applied: Map<BackupPart, Int>,
    /** The usage part was in the selection but a connection is running, so it was left alone (the running service owns that file). */
    val usageSkipped: Boolean,
    /** Saving the links failed (the Keystore could not be written). */
    val secretsFailed: Boolean
)

/**
 * Reads the app's data into a [BackupDoc] and puts a [BackupDoc] back (update41). All of it is on-device storage; the
 * file goes wherever the person's file picker sends it. Nothing here runs by itself: only the Backup page calls it.
 */
object BackupStore {

    /** How many items each part holds right now, for the tiles on the Backup page. */
    suspend fun summarize(ctx: Context, store: SettingsStore): Map<BackupPart, Int> {
        val entries = store.exportPrefs()
        fun size(e: PrefEntry) = if (e.type == PrefType.SET) (e.value as List<*>).size else 1
        val out = LinkedHashMap<BackupPart, Int>()
        for (part in BackupPart.values()) {
            out[part] = when (part) {
                BackupPart.USAGE -> UsageFile.read(ctx.filesDir).all().size
                BackupPart.SECRETS -> store.loadLinkBook().profiles.size + (if (store.getServiceTokenSecret().isNullOrBlank()) 0 else 1)
                else -> entries.filter { BackupKeys.partOf(it.key) == part }.sumOf { size(it) }
            }
        }
        return out
    }

    suspend fun build(ctx: Context, store: SettingsStore, parts: Set<BackupPart>): BackupDoc {
        val entries = store.exportPrefs()
        val payload = LinkedHashMap<BackupPart, Any?>()
        for (part in parts) {
            payload[part] = when (part) {
                BackupPart.USAGE -> {
                    InsightHub.flushUsage?.invoke() // a running connection writes its newest totals first
                    UsageFile.read(ctx.filesDir).serialize()
                }
                BackupPart.SECRETS -> store.exportSecrets()
                else -> BackupKeys.encode(entries.filter { BackupKeys.partOf(it.key) == part })
            }
        }
        return BackupDoc(System.currentTimeMillis(), versionName(ctx), payload)
    }

    /** The parts of [doc] that hold something, with their item counts, for the restore choice. */
    fun contents(doc: BackupDoc): Map<BackupPart, Int> {
        val out = LinkedHashMap<BackupPart, Int>()
        for (part in BackupPart.values()) {
            if (!doc.parts.containsKey(part)) continue
            val raw = doc.parts[part]
            out[part] = when (part) {
                BackupPart.USAGE -> UsageLedger.parse(raw as? String).all().size
                BackupPart.SECRETS -> {
                    val m = raw as? Map<*, *>
                    LinkProfiles.decode(m?.get("links") as? String).profiles.size + (if ((m?.get("ztSecret") as? String).isNullOrBlank()) 0 else 1)
                }
                else -> BackupKeys.decode(raw).sumOf { if (it.type == PrefType.SET) (it.value as List<*>).size else 1 }
            }
        }
        return out
    }

    /**
     * Puts the chosen parts back. A part is applied only with the entries that really belong to it, whatever the file says.
     * [allowUsage] is false while a connection runs: the service keeps today's totals in memory and would overwrite the file.
     */
    suspend fun restore(ctx: Context, store: SettingsStore, doc: BackupDoc, parts: Set<BackupPart>, allowUsage: Boolean): RestoreReport {
        val applied = LinkedHashMap<BackupPart, Int>()
        var usageSkipped = false
        var secretsFailed = false
        for (part in parts) {
            if (!doc.parts.containsKey(part)) continue
            val raw = doc.parts[part]
            when (part) {
                BackupPart.USAGE -> {
                    if (!allowUsage) { usageSkipped = true; continue }
                    val fromBackup = UsageLedger.parse(raw as? String).all()
                    val merged = UsageMerge.merge(UsageFile.read(ctx.filesDir).all(), fromBackup)
                    UsageFile.write(ctx.filesDir, UsageLedger(merged).serialize())
                    applied[part] = fromBackup.size
                }
                BackupPart.SECRETS -> {
                    val r = store.importSecrets(raw)
                    if (r.failed) secretsFailed = true
                    applied[part] = r.linksAdded + (if (r.secretRestored) 1 else 0)
                }
                else -> {
                    val own = BackupKeys.decode(raw).filter { BackupKeys.partOf(it.key) == part }
                    applied[part] = store.importPrefs(own)
                }
            }
        }
        return RestoreReport(applied, usageSkipped, secretsFailed)
    }

    /** The picked file as text; null when it cannot be read or is too big to be a backup. */
    fun readText(ctx: Context, uri: Uri): String? = try {
        ctx.contentResolver.openInputStream(uri)?.use { input ->
            val bytes = input.readNBytesCompat(BackupFile.MAX_FILE_BYTES + 1)
            if (bytes.size > BackupFile.MAX_FILE_BYTES) null else String(bytes, Charsets.UTF_8)
        }
    } catch (_: IOException) {
        null
    } catch (_: SecurityException) {
        null
    }

    fun writeText(ctx: Context, uri: Uri, text: String): Boolean = try {
        ctx.contentResolver.openOutputStream(uri, "wt")?.use { it.write(text.toByteArray(Charsets.UTF_8)); it.flush(); true } ?: false
    } catch (_: IOException) {
        false
    } catch (_: SecurityException) {
        false
    }

    private fun java.io.InputStream.readNBytesCompat(max: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() < max) {
            val n = read(buf, 0, minOf(buf.size, max - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun versionName(ctx: Context): String =
        try { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName.orEmpty() } catch (_: Exception) { "" }
}
