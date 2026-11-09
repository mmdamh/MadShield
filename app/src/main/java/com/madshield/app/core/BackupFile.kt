package com.madshield.app.core

import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Backup (update41): the parts of the app's data a person can pick, and the file they are written to.
 * Pure Kotlin (no Android types), so the file format, the encryption and the safety checks are tested without a phone.
 */
enum class BackupPart(val id: String, val sensitive: Boolean = false) {
    /** Connection, DNS, DoH, engine and notification choices. */
    SETTINGS("settings"),
    /** Direct/block rules and the per-app choice. */
    ROUTING("routing"),
    /** Theme, colours, dark mode, connect-button shape. */
    APPEARANCE("appearance"),
    /** The daily usage totals (the statistics file). */
    USAGE("usage"),
    /** Saved custom links and the Zero Trust token: they hold UUIDs and passwords, so they are never on by default. */
    SECRETS("secrets", sensitive = true);

    companion object {
        fun fromId(id: String): BackupPart? = values().firstOrNull { it.id == id }
    }
}

enum class PrefType(val tag: String) {
    STRING("s"), BOOL("b"), INT("i"), LONG("l"), SET("ss");

    companion object {
        fun fromTag(tag: String?): PrefType? = values().firstOrNull { it.tag == tag }
    }
}

/** One stored setting: its name, its type and its value (String, Boolean, Int, Long or List<String>). */
class PrefEntry(val key: String, val type: PrefType, val value: Any)

object BackupKeys {
    /** Which part a stored setting belongs to. */
    fun partOf(key: String): BackupPart = when {
        key.startsWith("ui_") -> BackupPart.APPEARANCE
        key == "direct_rules" || key == "block_rules" || key == "app_selection_mode" || key == "selected_packages" -> BackupPart.ROUTING
        else -> BackupPart.SETTINGS
    }

    private val NAME = Regex("[a-z0-9_]{1,64}")
    private const val MAX_TEXT = 20_000
    private const val MAX_ITEMS = 5_000

    fun encode(entries: List<PrefEntry>): List<Map<String, Any?>> = entries.map {
        linkedMapOf<String, Any?>("k" to it.key, "t" to it.type.tag, "v" to it.value)
    }

    /** Reads entries back. Anything malformed (bad name, unknown type, wrong value shape, too long) is dropped, never trusted. */
    fun decode(raw: Any?): List<PrefEntry> = (raw as? List<*>).orEmpty().mapNotNull { item ->
        val m = item as? Map<*, *> ?: return@mapNotNull null
        val key = m["k"] as? String ?: return@mapNotNull null
        if (!NAME.matches(key)) return@mapNotNull null
        val type = PrefType.fromTag(m["t"] as? String) ?: return@mapNotNull null
        val v = m["v"]
        val value: Any = when (type) {
            PrefType.STRING -> (v as? String)?.takeIf { it.length <= MAX_TEXT }
            PrefType.BOOL -> v as? Boolean
            PrefType.INT -> (v as? Number)?.toLong()?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
            PrefType.LONG -> (v as? Number)?.toLong()
            PrefType.SET -> (v as? List<*>)?.takeIf { it.size <= MAX_ITEMS && it.all { s -> s is String && s.length <= MAX_TEXT } }
                ?.map { it as String }
        } ?: return@mapNotNull null
        PrefEntry(key, type, value)
    }
}

/** Everything in a backup: when it was made, by which app version, and the payload of each part that was chosen. */
class BackupDoc(val createdMs: Long, val appVersion: String, val parts: Map<BackupPart, Any?>)

sealed class BackupRead {
    class Ok(val doc: BackupDoc) : BackupRead()
    /** The file is protected and no password was given. */
    data object NeedsPassword : BackupRead()
    /** The password is wrong, or the file was changed after it was made (the two cannot be told apart, on purpose). */
    data object WrongPasswordOrDamaged : BackupRead()
    /** Not a MadShield backup, or from a newer format. */
    data object Invalid : BackupRead()
}

object BackupFile {
    const val FORMAT = 1
    const val DEFAULT_ITERATIONS = 150_000
    private const val MIN_ITERATIONS = 1_000
    private const val MAX_ITERATIONS = 2_000_000
    private const val MAGIC = "madshield-backup"
    private const val AAD = "madshield-backup-1"
    /** A backup is a few KB to a few hundred KB; anything bigger is not one and is not even parsed. */
    const val MAX_FILE_BYTES = 8 * 1024 * 1024

    private val random = SecureRandom()

    /** The file text. With a non-blank [password] the whole content is encrypted (AES-256-GCM, key from PBKDF2-SHA256). */
    fun write(doc: BackupDoc, password: String?, iterations: Int = DEFAULT_ITERATIONS): String {
        val plain = MiniJson.write(
            linkedMapOf<String, Any?>(
                "app" to MAGIC, "format" to FORMAT, "created" to doc.createdMs, "appVersion" to doc.appVersion,
                "parts" to doc.parts.entries.associateTo(linkedMapOf<String, Any?>()) { it.key.id to it.value }
            )
        )
        if (password.isNullOrEmpty()) return plain
        val salt = ByteArray(16).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)
        val enc = Base64.getEncoder()
        val data = cipher(Cipher.ENCRYPT_MODE, password, salt, iv, iterations).doFinal(plain.toByteArray(Charsets.UTF_8))
        return MiniJson.write(
            linkedMapOf<String, Any?>(
                "app" to MAGIC, "format" to FORMAT,
                "enc" to linkedMapOf<String, Any?>(
                    "kdf" to "pbkdf2-sha256", "iter" to iterations,
                    "salt" to enc.encodeToString(salt), "iv" to enc.encodeToString(iv), "data" to enc.encodeToString(data)
                )
            )
        )
    }

    fun isEncrypted(text: String): Boolean = headerOf(text)?.containsKey("enc") == true

    fun read(text: String, password: String?): BackupRead {
        if (text.length > MAX_FILE_BYTES) return BackupRead.Invalid
        val root = headerOf(text) ?: return BackupRead.Invalid
        val plainRoot: Map<String, Any?> = if (root.containsKey("enc")) {
            if (password.isNullOrEmpty()) return BackupRead.NeedsPassword
            val enc = root["enc"] as? Map<*, *> ?: return BackupRead.Invalid
            val iter = (enc["iter"] as? Number)?.toInt() ?: return BackupRead.Invalid
            if (enc["kdf"] != "pbkdf2-sha256" || iter !in MIN_ITERATIONS..MAX_ITERATIONS) return BackupRead.Invalid
            val salt = b64(enc["salt"]) ?: return BackupRead.Invalid
            val iv = b64(enc["iv"]) ?: return BackupRead.Invalid
            val data = b64(enc["data"]) ?: return BackupRead.Invalid
            if (salt.size != 16 || iv.size != 12) return BackupRead.Invalid
            val bytes = try {
                cipher(Cipher.DECRYPT_MODE, password, salt, iv, iter).doFinal(data)
            } catch (_: GeneralSecurityException) {
                return BackupRead.WrongPasswordOrDamaged
            }
            headerOf(String(bytes, Charsets.UTF_8)) ?: return BackupRead.WrongPasswordOrDamaged
        } else root

        val partsRaw = plainRoot["parts"] as? Map<*, *> ?: return BackupRead.Invalid
        val parts = LinkedHashMap<BackupPart, Any?>()
        for ((k, v) in partsRaw) {
            // A part this version does not know is skipped, so a newer file still restores what it can.
            BackupPart.fromId(k as? String ?: continue)?.let { parts[it] = v }
        }
        val created = (plainRoot["created"] as? Number)?.toLong() ?: 0L
        return BackupRead.Ok(BackupDoc(created, (plainRoot["appVersion"] as? String).orEmpty().take(40), parts))
    }

    /** The top-level object when [text] is a MadShield backup of a format this version understands, else null. */
    private fun headerOf(text: String): Map<String, Any?>? {
        val root = MiniJson.parseObject(text) ?: return null
        if (root["app"] != MAGIC) return null
        val format = (root["format"] as? Number)?.toInt() ?: return null
        return if (format in 1..FORMAT) root else null
    }

    private fun b64(v: Any?): ByteArray? {
        val text = v as? String ?: return null
        return try { Base64.getDecoder().decode(text) } catch (_: IllegalArgumentException) { null }
    }

    private fun cipher(mode: Int, password: String, salt: ByteArray, iv: ByteArray, iterations: Int): Cipher {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
        val key = try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            updateAAD(AAD.toByteArray(Charsets.US_ASCII))
        }
    }
}

/** How a restored usage file is merged: days in the backup replace the same days here, other days stay. Never double-counts. */
object UsageMerge {
    fun merge(current: List<DayUsage>, fromBackup: List<DayUsage>): List<DayUsage> {
        val byDay = java.util.TreeMap<String, DayUsage>()
        for (d in current) byDay[d.day] = d
        for (d in fromBackup) byDay[d.day] = d
        return byDay.values.toList()
    }
}

/** How restored custom links join the ones already saved: nothing is lost or replaced, a link already present is not added twice. */
object LinkBookMerge {
    fun merge(current: LinkProfileBook, incoming: LinkProfileBook): LinkProfileBook {
        val haveLinks = current.profiles.map { it.link }.toMutableSet()
        val haveIds = current.profiles.map { it.id }.toMutableSet()
        val merged = current.profiles.toMutableList()
        for (p in incoming.profiles) {
            if (merged.size >= LinkProfiles.MAX_PROFILES) break
            if (!haveLinks.add(p.link)) continue
            var id = p.id
            while (!haveIds.add(id)) id += "-r"
            merged.add(p.copy(id = id))
        }
        // The active link stays what it is; only when none was active does the backup's active one take over.
        val active = current.activeId ?: incoming.active?.link?.let { link -> merged.firstOrNull { it.link == link }?.id }
        return LinkProfileBook(merged, active)
    }
}
