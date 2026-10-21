# Keep it boring on purpose. No reflection-heavy third-party SDKs to special-case
# because there aren't any. Compose + AndroidX default rules cover this app.

# androidx.security:security-crypto pulls in Google Tink, which references a
# handful of compile-time-only annotations (error-prone, javax.annotation)
# that aren't on the runtime classpath. They're annotations only -- nothing
# actually calls into them at runtime -- so telling R8 not to worry about
# their absence is the correct fix, not a workaround for a real problem.
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**

# Strip Log.* calls entirely from release bytecode as a second belt-and-suspenders
# layer on top of the app never writing persistent logs in the first place.
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# OkHttp (core/DohClient.kt). It ships its own consumer rules; these only silence optional TLS providers that
# are not on the classpath (OkHttp checks for them at runtime and falls back to the platform).
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
