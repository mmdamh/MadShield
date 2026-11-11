import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    kotlin("jvm") version "1.9.24"
    id("org.jetbrains.compose") version "1.6.11"
}

group = "com.madshield"
version = "1.0.0"

kotlin { jvmToolchain(17) }

// The desktop version reuses the app's pure Kotlin (no Android, no coroutines, no OkHttp), the same set
// scripts/run-pure-tests.sh compiles. It is copied, not moved: the Android build is not touched.
val androidSrc = layout.projectDirectory.dir("../app/src/main/java/com/madshield/app")
val sharedSrc = layout.buildDirectory.dir("shared-src")
val syncShared by tasks.registering(Sync::class) {
    from(androidSrc) {
        include("core/*.kt", "util/*.kt")
        val impure = Regex("(?m)^import (android|androidx|kotlinx\\.coroutines|okhttp3)")
        eachFile { if (impure.containsMatchIn(file.readText())) exclude() }
    }
    into(sharedSrc.map { it.dir("com/madshield/app") })
}
sourceSets["main"].kotlin.srcDir(sharedSrc)
tasks.named("compileKotlin") { dependsOn(syncShared) }

dependencies {
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.8.1")
    // The Foxy sign-in runs in an embedded browser (JavaFX WebView) on Mozilla's own page.
    for (m in listOf("base", "graphics", "controls", "media", "web", "swing")) {
        implementation("org.openjfx:javafx-$m:21.0.5:win")
    }
    testImplementation(kotlin("test"))
}

compose.desktop {
    application {
        mainClass = "com.madshield.desktop.MainKt"
        nativeDistributions {
            targetFormats(TargetFormat.Msi)
            packageName = "MadShield"
            packageVersion = "1.0.0"
            description = "MadShield for Windows"
            vendor = "MadShield"
            includeAllModules = true
            // CI copies aether.exe, sing-box.exe, madshield-fx.exe and pt/ into engines-pack/windows-x64/
            appResourcesRootDir.set(layout.projectDirectory.dir("engines-pack"))
            windows { menuGroup = "MadShield"; console = false }
        }
    }
}

// `gradle selftest` runs the real connection code without a window (CI, on an administrator runner).
tasks.register<JavaExec>("selftest") {
    group = "verification"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.madshield.desktop.MainKt")
    args("--selftest")
    environment("MADSHIELD_KIT", layout.projectDirectory.dir("engines-pack/windows-x64").asFile.absolutePath)
}
