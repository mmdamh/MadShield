package com.madshield.desktop

import java.io.File

/** Where the engine programs are: next to the app in an installed copy, or MADSHIELD_KIT while developing. */
object Kit {
    val dir: File = locate()
    val aether = File(dir, "aether.exe")
    val singBox = File(dir, "sing-box.exe")
    val fx = File(dir, "madshield-fx.exe")
    val ptDir = File(dir, "pt")
    val psiphon = File(ptDir, "psiphon-tunnel-core.exe")

    private fun locate(): File {
        val candidates = listOfNotNull(
            System.getenv("MADSHIELD_KIT"),
            System.getProperty("compose.application.resources.dir"),
            File(System.getProperty("user.dir"), "engines-pack/windows-x64").path
        ).map(::File)
        return candidates.firstOrNull { File(it, "sing-box.exe").isFile } ?: candidates.first()
    }

    /** What is missing from the kit for this engine, or null when it is complete. */
    fun missing(vararg needed: File): String? =
        needed.firstOrNull { !it.isFile }?.let { "${it.name} is missing from ${dir.path}. Reinstall MadShield." }
}

/** Everything the app writes lives under %LOCALAPPDATA%\MadShield (per user). */
object DataDir {
    val root: File = File(System.getenv("LOCALAPPDATA") ?: System.getProperty("user.home"), "MadShield").also { it.mkdirs() }
    fun sub(name: String): File = File(root, name).also { it.mkdirs() }
}

object Elevation {
    /** `fltmc` only works for an administrator: exit code 0 means this process is elevated. */
    fun isAdmin(): Boolean = try {
        val p = ProcessBuilder("fltmc").redirectErrorStream(true).start()
        p.inputStream.readBytes()
        p.waitFor() == 0
    } catch (_: Exception) { false }

    /** Starts the same program again through the UAC prompt. True when the request was made (the caller then exits). */
    fun relaunch(args: Array<String>): Boolean = try {
        val info = ProcessHandle.current().info()
        val cmd = info.command().orElse(null) ?: return false
        val all = info.arguments().orElse(emptyArray()).toList() + args
        fun q(s: String) = "'" + s.replace("'", "''") + "'"
        val script = "Start-Process -FilePath ${q(cmd)} " +
            (if (all.isNotEmpty()) "-ArgumentList ${all.joinToString(",") { q(it) }} " else "") + "-Verb RunAs"
        ProcessBuilder("powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script).start()
        true
    } catch (_: Exception) { false }
}

/**
 * The names of this app's own programs. They, and the engines, must never enter the tunnel (that would be a loop): the
 * TUN configuration sends them out directly. The routing front's DIRECT connections leave from this app too.
 */
object Own {
    val processNames: List<String> by lazy {
        val own = ProcessHandle.current().info().command().map { File(it).name }.orElse(null)
        listOfNotNull(own, "MadShield.exe", "java.exe", "javaw.exe").distinct() +
            listOf("aether.exe", "psiphon-tunnel-core.exe", "lyrebird.exe", "madshield-fx.exe", "sing-box.exe")
    }
}

/** Stops the engines if this app disappears without cleaning up (see guardian.ps1). */
object Guardian {
    private var proc: Process? = null

    @Synchronized
    fun arm() {
        disarm()
        try {
            val script = File(DataDir.root, "guardian.ps1")
            val text = Guardian::class.java.getResourceAsStream("/guardian.ps1")?.use { it.readBytes() } ?: return
            script.writeBytes(text)
            proc = ProcessBuilder(
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                "-File", script.absolutePath, "-ParentPid", ProcessHandle.current().pid().toString(), "-Kit", Kit.dir.absolutePath
            ).redirectErrorStream(true).start().also { p -> Thread { runCatching { p.inputStream.readBytes() } }.apply { isDaemon = true }.start() }
        } catch (_: Exception) { /* without it a crash can leave the tunnel up; the app still works */ }
    }

    @Synchronized
    fun disarm() {
        proc?.destroyForcibly()
        proc = null
    }
}
