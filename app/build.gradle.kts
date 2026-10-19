plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing key, decoded by CI from the SIGNING_KEY_BASE64 secret (see build.yml).
// When it is absent (first build, no secrets set up yet) the release APK is signed with
// the debug key instead of failing the build, so you always get an installable APK.
// Switching to a real key later means uninstalling once, because the signature changes.
val releaseKeystoreFile = file(System.getenv("KEYSTORE_PATH") ?: "${rootProject.projectDir}/release.keystore")

android {
    namespace = "com.aethershield.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.aethershield.app"
        minSdk = 26 // VpnService.Builder per-app APIs need 21+, but 26 keeps things sane/modern
        targetSdk = 35
        versionCode = 5
        versionName = "0.3.2"

        // Stamped at CI build time from native/aether-core/CORE_VERSION and
        // native/hev-socks5-tunnel/CORE_VERSION -- see .github/workflows/build.yml.
        // Left blank here; CI replaces these via resValue before assembling release.
        buildConfigField("String", "ENGINE_COMMIT", "\"unset\"")
        buildConfigField("String", "TUN2SOCKS_COMMIT", "\"unset\"")

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    // Reads the keystore CI decodes at repo root (see .github/workflows/build.yml,
    // "Decode signing key") plus its passwords from env vars. Locally, these
    // env vars just won't be set, the keystore file won't exist, and the
    // signing config quietly no-ops -- assembleDebug works fine without any
    // of this; only assembleRelease needs it.
    signingConfigs {
        create("release") {
            if (releaseKeystoreFile.exists()) {
                storeFile = releaseKeystoreFile
                storePassword = System.getenv("KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Release builds are never debuggable and never backed up.
            isDebuggable = false
            signingConfig = if (releaseKeystoreFile.exists()) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
        debug {
            applicationIdSuffix = ".debug"
            isDebuggable = true
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        // Native engine binaries are shipped as jniLibs (see CI workflow), named like
        // libaether.so / libtun2socks.so, NOT as raw assets. This is required, not
        // stylistic: since Android 10, apps can only execute native binaries that live
        // in applicationInfo.nativeLibraryDir (the W^X exemption), and that directory
        // is only populated when libs are extracted at install time -- hence "true"
        // here rather than the newer compressed/non-extracted default.
        jniLibs.useLegacyPackaging = true
        // CI stamps the SHA-256 of each native file and the app checks them at engine start
        // (BinaryIntegrity). Stripping would rewrite the bytes after the hash was taken.
        jniLibs.keepDebugSymbols += "**/*.so"
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.navigation:navigation-compose:2.7.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Local, on-device settings only -- no cloud sync, no analytics SDK of any kind.
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    // Keystore-backed encryption for the few secrets that exist (e.g. an optional
    // Zero Trust service token), never stored in plaintext prefs.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
