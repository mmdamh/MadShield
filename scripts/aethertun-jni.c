/*
 * aethertun-jni.c -- MadShield's OWN JNI bridge to hev-socks5-tunnel.
 *
 * This exists because of a real, documented crash class: loading
 * hev-socks5-tunnel directly and relying on ITS bundled JNI glue
 * (hev-jni.c) couples your Kotlin declarations to whatever JNI signatures
 * upstream happens to ship on a given day. When those drift (they have,
 * historically -- e.g. TProxyStartService going from returning void to
 * returning boolean), RegisterNatives fails inside hev's own JNI_OnLoad,
 * System.loadLibrary() throws, and full-device VPN mode dies while
 * proxy-only mode (which never loads hev) keeps working. That symptom --
 * "proxy works, full VPN mode crashes/won't connect" -- is exactly what
 * this bridge fixes, categorically:
 *
 *  - It binds ONLY hev's stable public C API (hev-main.h):
 *      hev_socks5_tunnel_main / hev_socks5_tunnel_quit / hev_socks5_tunnel_stats
 *    linked with -Wl,--no-undefined, so if upstream ever removes/renames
 *    one of these, the CI BUILD fails loudly instead of shipping a broken APK.
 *  - It exports conventional Java_* symbols WE control, matching the Kotlin
 *    external fun declarations in vpn/TProxyService.kt exactly.
 *  - It defines its OWN JNI_OnLoad. This matters: ART locates JNI_OnLoad via
 *    dlsym() on the loaded library's handle, and dlsym() searches the
 *    library AND its DT_NEEDED dependencies -- so without this, ART could
 *    find hev's OWN JNI_OnLoad (if it's still present in the linked .so) and
 *    run its RegisterNatives anyway, hitting the same signature-drift crash.
 *    The build step that compiles this also strips hev-jni.c out of the hev
 *    build entirely, so there is no foreign JNI_OnLoad left to find.
 *
 * THREADING -- do not "simplify" this: the tunnel event loop MUST run on a
 * plain native pthread, not on an ART-attached Java thread. hev-task-system
 * implements its coroutines by swapping the thread's stack pointer; doing
 * that on a thread ART manages corrupts what the runtime expects of the
 * stack and kills the whole app with a native SIGSEGV shortly after real
 * traffic starts (with nothing useful in the Java-level crash log -- this is
 * a strong candidate for what "دائم کرش میکنه" was actually hitting even
 * before the symbol-name issue). It also has to run in-process, since the
 * VpnService TUN fd is only valid inside this process.
 */

#include <jni.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

/* hev-socks5-tunnel's stable public C API (include/hev-main.h). */
extern int hev_socks5_tunnel_main(const char *config_path, int tun_fd);
extern void hev_socks5_tunnel_quit(void);
extern void hev_socks5_tunnel_stats(size_t *tx_packets, size_t *tx_bytes,
                                    size_t *rx_packets, size_t *rx_bytes);

#define TAG "aethertun"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)vm;
    (void)reserved;
    LOGI("libaethertun loaded: conventional Java_* bindings; hev's own JNI layer unused");
    return JNI_VERSION_1_6;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static bool running = false;

typedef struct {
    char *config_path;
    int tun_fd;
} StartArgs;

static void *
tunnel_thread(void *data)
{
    StartArgs *args = (StartArgs *)data;
    int res;

    LOGI("tunnel loop starting on native pthread (fd=%d)", args->tun_fd);
    res = hev_socks5_tunnel_main(args->config_path, args->tun_fd);
    LOGI("tunnel loop exited (res=%d)", res);

    pthread_mutex_lock(&lock);
    running = false;
    pthread_mutex_unlock(&lock);

    free(args->config_path);
    free(args);
    return NULL;
}

JNIEXPORT jboolean JNICALL
Java_com_aethershield_app_vpn_TProxyService_TProxyStartService(JNIEnv *env,
                                                                jclass clazz,
                                                                jstring config_path,
                                                                jint tun_fd)
{
    const char *path = NULL;
    StartArgs *args = NULL;
    pthread_attr_t attr;
    pthread_t thread;
    int rc;

    (void)clazz;

    pthread_mutex_lock(&lock);
    if (running) {
        pthread_mutex_unlock(&lock);
        LOGI("tunnel already running; start request ignored");
        return JNI_TRUE;
    }
    running = true; /* claimed; rolled back on any failure below */
    pthread_mutex_unlock(&lock);

    path = (*env)->GetStringUTFChars(env, config_path, NULL);
    if (!path)
        goto fail;

    args = (StartArgs *)malloc(sizeof(StartArgs));
    if (!args) {
        (*env)->ReleaseStringUTFChars(env, config_path, path);
        goto fail;
    }
    args->config_path = strdup(path);
    args->tun_fd = (int)tun_fd;
    (*env)->ReleaseStringUTFChars(env, config_path, path);
    if (!args->config_path) {
        free(args);
        goto fail;
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attr, tunnel_thread, args);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        LOGE("pthread_create failed: %d", rc);
        free(args->config_path);
        free(args);
        goto fail;
    }
    return JNI_TRUE;

fail:
    pthread_mutex_lock(&lock);
    running = false;
    pthread_mutex_unlock(&lock);
    return JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_aethershield_app_vpn_TProxyService_TProxyStopService(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    hev_socks5_tunnel_quit();
}

JNIEXPORT jboolean JNICALL
Java_com_aethershield_app_vpn_TProxyService_TProxyIsRunning(JNIEnv *env, jclass clazz)
{
    jboolean value;

    (void)env;
    (void)clazz;

    pthread_mutex_lock(&lock);
    value = running ? JNI_TRUE : JNI_FALSE;
    pthread_mutex_unlock(&lock);
    return value;
}

JNIEXPORT jlongArray JNICALL
Java_com_aethershield_app_vpn_TProxyService_TProxyGetStats(JNIEnv *env, jclass clazz)
{
    size_t tx_packets = 0, tx_bytes = 0, rx_packets = 0, rx_bytes = 0;
    jlong values[4];
    jlongArray result;

    (void)clazz;

    hev_socks5_tunnel_stats(&tx_packets, &tx_bytes, &rx_packets, &rx_bytes);

    values[0] = (jlong)tx_packets;
    values[1] = (jlong)tx_bytes;
    values[2] = (jlong)rx_packets;
    values[3] = (jlong)rx_bytes;

    result = (*env)->NewLongArray(env, 4);
    if (!result)
        return NULL;
    (*env)->SetLongArrayRegion(env, result, 0, 4, values);
    return result;
}
