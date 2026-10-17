pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    // Only Google + Maven Central. No third-party/unknown repos, on purpose —
    // this is part of the "nothing unaudited gets pulled in" posture.
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "AetherShieldVPN"
include(":app")
