package com.madshield.app.core

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal, dependency-free ELF reader used as a PRE-FLIGHT check before the
 * engine is launched.
 *
 * Why it exists: when the native engine was built against a *shared* C++
 * runtime, Android's linker refuses to start it with
 *   CANNOT LINK EXECUTABLE ... library "libc++_shared.so" not found
 * and the only symptom in the app used to be "stuck on Connecting" until the
 * timeout. Reading the binary's DT_NEEDED list ourselves lets the app say what
 * is actually wrong, immediately, instead of waiting for a timeout.
 *
 * It only ever READS the file (never executes it) and rejects anything that is
 * not a well-formed little-endian ELF, so a truncated or tampered payload
 * produces a clear error rather than an obscure crash.
 */
object ElfInspector {

    const val EM_ARM = 40
    const val EM_X86_64 = 62
    const val EM_AARCH64 = 183

    data class Info(
        val is64Bit: Boolean,
        val machine: Int,
        /** DT_NEEDED entries, e.g. ["libc.so", "libm.so", "libdl.so"]. */
        val needed: List<String>
    ) {
        val machineName: String
            get() = when (machine) {
                EM_AARCH64 -> "arm64-v8a"
                EM_ARM -> "armeabi-v7a"
                EM_X86_64 -> "x86_64"
                else -> "machine#$machine"
            }
    }

    private const val PT_LOAD = 1
    private const val PT_DYNAMIC = 2
    private const val DT_NULL = 0L
    private const val DT_NEEDED = 1L
    private const val DT_STRTAB = 5L

    /** @throws IOException if [file] is not a valid little-endian ELF image. */
    fun inspect(file: File): Info {
        RandomAccessFile(file, "r").use { raf ->
            val length = raf.length()
            if (length < 64) throw IOException("not an ELF file: too small")

            val ident = ByteArray(16)
            raf.readFully(ident)
            if (ident[0].toInt() != 0x7f || ident[1] != 'E'.code.toByte() ||
                ident[2] != 'L'.code.toByte() || ident[3] != 'F'.code.toByte()
            ) throw IOException("not an ELF file: bad magic")
            val is64 = when (ident[4].toInt()) {
                1 -> false
                2 -> true
                else -> throw IOException("not an ELF file: bad class")
            }
            if (ident[5].toInt() != 1) throw IOException("unsupported ELF byte order")

            val headerSize = if (is64) 64 else 52
            val header = ByteBuffer.allocate(headerSize).order(ByteOrder.LITTLE_ENDIAN)
            raf.seek(0)
            raf.readFully(header.array())

            val machine = header.getShort(18).toInt() and 0xffff
            val phoff: Long
            val phentsize: Int
            val phnum: Int
            if (is64) {
                phoff = header.getLong(32)
                phentsize = header.getShort(54).toInt() and 0xffff
                phnum = header.getShort(56).toInt() and 0xffff
            } else {
                phoff = header.getInt(28).toLong() and 0xffffffffL
                phentsize = header.getShort(42).toInt() and 0xffff
                phnum = header.getShort(44).toInt() and 0xffff
            }
            if (phnum == 0 || phentsize < 32 || phoff <= 0 || phoff + phnum.toLong() * phentsize > length)
                throw IOException("ELF program headers are out of range")

            class Seg(val type: Int, val offset: Long, val vaddr: Long, val filesz: Long)

            val segments = ArrayList<Seg>(phnum)
            val ph = ByteBuffer.allocate(phentsize).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0 until phnum) {
                raf.seek(phoff + i.toLong() * phentsize)
                raf.readFully(ph.array())
                segments += if (is64) {
                    Seg(ph.getInt(0), ph.getLong(8), ph.getLong(16), ph.getLong(32))
                } else {
                    Seg(
                        ph.getInt(0),
                        ph.getInt(4).toLong() and 0xffffffffL,
                        ph.getInt(8).toLong() and 0xffffffffL,
                        ph.getInt(16).toLong() and 0xffffffffL
                    )
                }
            }

            val dynamic = segments.firstOrNull { it.type == PT_DYNAMIC }
                ?: return Info(is64, machine, emptyList()) // static binary: nothing needed
            if (dynamic.offset < 0 || dynamic.filesz <= 0 || dynamic.offset + dynamic.filesz > length)
                throw IOException("ELF dynamic section is out of range")

            fun vaddrToOffset(vaddr: Long): Long {
                for (s in segments) {
                    if (s.type == PT_LOAD && vaddr >= s.vaddr && vaddr < s.vaddr + s.filesz) {
                        return s.offset + (vaddr - s.vaddr)
                    }
                }
                throw IOException("ELF string table address is not mapped")
            }

            val entrySize = if (is64) 16 else 8
            val dyn = ByteArray(dynamic.filesz.toInt().coerceAtMost(1 shl 20))
            raf.seek(dynamic.offset)
            raf.readFully(dyn)
            val buf = ByteBuffer.wrap(dyn).order(ByteOrder.LITTLE_ENDIAN)

            val neededOffsets = ArrayList<Long>()
            var strtab = -1L
            var pos = 0
            while (pos + entrySize <= dyn.size) {
                val tag: Long
                val value: Long
                if (is64) {
                    tag = buf.getLong(pos); value = buf.getLong(pos + 8)
                } else {
                    tag = buf.getInt(pos).toLong(); value = buf.getInt(pos + 4).toLong() and 0xffffffffL
                }
                if (tag == DT_NULL) break
                when (tag) {
                    DT_NEEDED -> neededOffsets += value
                    DT_STRTAB -> strtab = value
                }
                pos += entrySize
            }
            if (neededOffsets.isEmpty()) return Info(is64, machine, emptyList())
            if (strtab < 0) throw IOException("ELF has DT_NEEDED but no string table")

            val strBase = vaddrToOffset(strtab)
            val names = neededOffsets.map { off ->
                readCString(raf, strBase + off, length)
            }
            return Info(is64, machine, names)
        }
    }

    private fun readCString(raf: RandomAccessFile, offset: Long, fileLength: Long): String {
        if (offset < 0 || offset >= fileLength) throw IOException("ELF string offset is out of range")
        raf.seek(offset)
        val out = StringBuilder()
        while (out.length < 256) {
            val b = raf.read()
            if (b <= 0) break
            out.append(b.toChar())
        }
        return out.toString()
    }
}
