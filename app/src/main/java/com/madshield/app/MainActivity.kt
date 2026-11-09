package com.madshield.app

import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBars
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.lifecycle.lifecycleScope
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.madshield.app.core.*
import com.madshield.app.ui.*
import com.madshield.app.ui.components.FloatingNavBar
import com.madshield.app.ui.components.Motion
import com.madshield.app.ui.components.Tab
import com.madshield.app.ui.theme.MadShieldTheme
import com.madshield.app.ui.theme.DarkMode
import com.madshield.app.ui.theme.UiPrefs
import com.madshield.app.vpn.AetherVpnService
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var settingsStore: SettingsStore
    private var pendingConnect = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK && pendingConnect) {
            startForegroundService(Intent(this, AetherVpnService::class.java).setAction(AetherVpnService.ACTION_CONNECT))
        } else if (pendingConnect) {
            // The user denied the VPN permission dialog: don't leave the UI stuck on "Connecting".
            AetherController.setState(ConnectionState.Idle)
        }
        pendingConnect = false
    }

    // ---- permission prompts: notifications and battery optimization ---------------------------------------
    // Asked once on the first start, and again when the person turns on something that needs them (Settings).
    // Our own short dialog comes first, then Android's. Nothing here runs on a timer.
    private var permPrompt by mutableStateOf<PermKind?>(null)
    private var permChain = false
    private val permSkipped = mutableSetOf<PermKind>()
    private val permPrefs by lazy { getSharedPreferences("perm", MODE_PRIVATE) }

    private val notifPermLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { afterPermission() }
    private val settingsLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { afterPermission() }

    private fun pendingPermission(): PermKind? = when {
        PermKind.NOTIFICATIONS !in permSkipped && !Perms.notificationsAllowed(this) -> PermKind.NOTIFICATIONS
        PermKind.BATTERY !in permSkipped && !Perms.batteryExempt(this) -> PermKind.BATTERY
        else -> null
    }

    private fun firstRunPermissions() {
        if (permPrefs.getBoolean("asked", false)) return
        permChain = true
        permPrompt = pendingPermission()
        if (permPrompt == null) permPrefs.edit().putBoolean("asked", true).apply()
    }

    private fun askPermission(kind: PermKind) {
        permChain = false
        permSkipped.remove(kind)
        permPrompt = kind
    }

    private fun advancePermissions() {
        permPrompt = if (permChain) pendingPermission() else null
        if (permPrompt == null) permPrefs.edit().putBoolean("asked", true).apply()
    }

    private fun permissionLater() {
        permPrompt?.let { permSkipped.add(it) }
        advancePermissions()
    }

    private fun afterPermission() {
        permPrompt?.let { permSkipped.add(it) }
        advancePermissions()
    }

    private fun permissionAllow() {
        when (permPrompt ?: return) {
            PermKind.NOTIFICATIONS -> {
                val runtime = android.os.Build.VERSION.SDK_INT >= 33 &&
                    androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) !=
                    android.content.pm.PackageManager.PERMISSION_GRANTED &&
                    !permPrefs.getBoolean("notif_requested", false)
                if (runtime) {
                    permPrefs.edit().putBoolean("notif_requested", true).apply()
                    notifPermLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    // Already asked before (Android then stays silent) or switched off in Settings: open the page.
                    launchSystemPage(Perms.notificationSettingsIntent(this), null)
                }
            }
            PermKind.BATTERY -> launchSystemPage(Perms.batteryRequestIntent(this), Perms.batteryListIntent())
        }
    }

    private fun launchSystemPage(intent: Intent, fallback: Intent?) {
        try {
            settingsLauncher.launch(intent)
        } catch (_: Exception) {
            try {
                if (fallback != null) settingsLauncher.launch(fallback) else afterPermission()
            } catch (_: Exception) { afterPermission() }
        }
    }

    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(com.madshield.app.core.AppLanguage.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settingsStore = SettingsStore(this)
        if (savedInstanceState == null) firstRunPermissions()
        // The automatic clean-up has no timer: it is asked here, acts at most once a day, and only when idle.
        lifecycleScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            runCatching { StorageAuto.runIfDue(applicationContext, settingsStore) }
        }

        setContent {
            val uiPrefs by settingsStore.uiPrefsFlow.collectAsState(initial = UiPrefs())
            val systemDark = isSystemInDarkTheme()
            val dark = when (uiPrefs.darkMode) {
                DarkMode.SYSTEM -> systemDark
                DarkMode.LIGHT -> false
                DarkMode.DARK -> true
            }
            // Transparent bars, with icon colours that follow the in-app dark mode (not just the system's).
            DisposableEffect(dark) {
                val style = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT) { dark }
                enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
                onDispose { }
            }

            MadShieldTheme(uiPrefs) {
                val nav = rememberNavController()
                val config by settingsStore.configFlow.collectAsState(initial = EngineConfig())
                // The single source of truth for "are we connected": the real service, health-checked.
                val connectionState by AetherController.state.collectAsState()
                var tab by rememberSaveable { mutableStateOf(Tab.Home) }

                // "Reconnect to apply": what the running connection was started with. A change the engine reads only while
                // it starts (see RestartKey) asks once, a moment after the last edit; "Later" keeps quiet until the next change.
                var applied by remember { mutableStateOf<com.madshield.app.core.RestartKey?>(null) }
                var laterKey by remember { mutableStateOf<com.madshield.app.core.RestartKey?>(null) }
                var askReconnect by remember { mutableStateOf(false) }
                val nowKey = remember(config) { config.restartKey() }
                LaunchedEffect(connectionState) {
                    when (connectionState) {
                        is ConnectionState.Connecting -> { applied = settingsStore.configFlow.first().restartKey(); laterKey = null }
                        is ConnectionState.Connected -> if (applied == null) applied = settingsStore.configFlow.first().restartKey()
                        is ConnectionState.Idle, is ConnectionState.Error -> { applied = null; laterKey = null; askReconnect = false }
                        else -> {}
                    }
                }
                LaunchedEffect(nowKey, applied, laterKey, connectionState) {
                    val a = applied
                    if (a != null && connectionState is ConnectionState.Connected && nowKey != a && nowKey != laterKey) {
                        kotlinx.coroutines.delay(1_500)
                        askReconnect = true
                    } else {
                        askReconnect = false
                    }
                }
                if (askReconnect) {
                    androidx.compose.material3.AlertDialog(
                        onDismissRequest = { laterKey = nowKey; askReconnect = false },
                        title = { androidx.compose.material3.Text(androidx.compose.ui.res.stringResource(R.string.reconnect_title)) },
                        text = { androidx.compose.material3.Text(androidx.compose.ui.res.stringResource(R.string.reconnect_body)) },
                        confirmButton = {
                            androidx.compose.material3.TextButton(onClick = { askReconnect = false; reconnect(config) }) {
                                androidx.compose.material3.Text(androidx.compose.ui.res.stringResource(R.string.reconnect_now))
                            }
                        },
                        dismissButton = {
                            androidx.compose.material3.TextButton(onClick = { laterKey = nowKey; askReconnect = false }) {
                                androidx.compose.material3.Text(androidx.compose.ui.res.stringResource(R.string.reconnect_later))
                            }
                        }
                    )
                }

                // Edge-to-edge: the window is not resized for the keyboard, so every screen is padded by the
                // keyboard's height here, once. Fields at the bottom of a page then stay visible and scroll into view.
                // New content comes from the reading-end side: the right in left-to-right layouts, the left in Persian.
                val dir = if (LocalLayoutDirection.current == LayoutDirection.Rtl) -1 else 1
                NavHost(
                    nav, startDestination = "main", modifier = Modifier.imePadding(),
                    enterTransition = { Motion.arrive(dir) },
                    exitTransition = { Motion.cover(dir) },
                    popEnterTransition = { Motion.arrive(-dir) },
                    popExitTransition = { Motion.cover(-dir) }
                ) {
                    composable("main") {
                        val top = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
                        val padding = PaddingValues(top = top)
                        Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
                            AnimatedContent(
                                targetState = tab,
                                transitionSpec = {
                                    // Further along the bar = arrives from the end side; back = from the start side.
                                    val step = if (targetState.ordinal >= initialState.ordinal) dir else -dir
                                    Motion.arrive(step) togetherWith Motion.cover(step)
                                },
                                label = "tabs"
                            ) { current ->
                                when (current) {
                                    Tab.Home -> HomeScreen(
                                        config = config,
                                        connectionState = connectionState,
                                        onUpdate = { t -> updateConfig(t) },
                                        onConnect = { requestConnect(config) },
                                        onDisconnect = { disconnect(config) },
                                        onOpenLog = { nav.navigate("log") },
                                        onOpenConnections = { nav.navigate("connections") },
                                        onOpenUsage = { nav.navigate("usage") },
                                        onOpenAdvanced = { nav.navigate("advanced") },
                                        onOpenFirefox = { nav.navigate("fxvpn") },
                                        connectStyle = uiPrefs.connectStyle,
                                        contentPadding = padding
                                    )
                                    Tab.Dns -> DnsScreen(config, { t -> updateConfig(t) }, padding, connectionState)
                                    Tab.Routing -> RoutingScreen(
                                        config,
                                        connectionState,
                                        onUpdate = { t -> updateConfig(t) },
                                        onOpenBypass = { nav.navigate("bypass") },
                                        onOpenApps = { nav.navigate("apps") },
                                        contentPadding = padding
                                    )
                                    Tab.Settings -> SettingsScreen(
                                        config,
                                        onUpdate = { t -> updateConfig(t) },
                                        onOpenAppearance = { nav.navigate("appearance") },
                                        onOpenAdvanced = { nav.navigate("advanced") },
                                        onOpenDiagnostics = { nav.navigate("diagnostics") },
                                        onOpenConnections = { nav.navigate("connections") },
                                        onOpenUsage = { nav.navigate("usage") },
                                        onOpenStorage = { nav.navigate("storage") },
                                        onOpenBackup = { nav.navigate("backup") },
                                        onAskPermission = { askPermission(it) },
                                        contentPadding = padding
                                    )
                                }
                            }
                            // The floating bar would ride on top of the keyboard, so it hides while typing.
                            val keyboardOpen = WindowInsets.ime.getBottom(LocalDensity.current) > 0
                            if (!keyboardOpen) Box(Modifier.align(Alignment.BottomCenter)) {
                                FloatingNavBar(current = tab, onSelect = { tab = it })
                            }
                        }
                    }
                    composable("bypass") {
                        BypassListScreen(config, { t -> updateConfig(t) }, { nav.popBackStack() })
                    }
                    composable("apps") {
                        AppExclusionScreen(
                            packageManager = packageManager,
                            selfPackage = packageName,
                            config = config,
                            onUpdate = { t -> updateConfig(t) },
                            onBack = { nav.popBackStack() }
                        )
                    }
                    composable("appearance") {
                        AppearanceScreen(uiPrefs, { t -> updateUi(t) }, { nav.popBackStack() })
                    }
                    composable("advanced") {
                        AdvancedScreen(config, { t -> updateConfig(t) }, { nav.popBackStack() })
                    }
                    composable("log") { LogScreen(onBack = { nav.popBackStack() }) }
                    composable("connections") { ConnectionsScreen(config, onBack = { nav.popBackStack() }) }
                    composable("usage") { UsageScreen(onBack = { nav.popBackStack() }) }
                    composable("fxvpn") { FirefoxVpnScreen(onBack = { nav.popBackStack() }) }
                    composable("storage") {
                        val prefs by settingsStore.storagePrefsFlow.collectAsState(initial = StoragePrefs())
                        StorageScreen(
                            prefs,
                            { t -> lifecycleScope.launch { settingsStore.updateStorage(t) } },
                            { nav.popBackStack() }
                        )
                    }
                    composable("backup") { BackupScreen(settingsStore, onBack = { nav.popBackStack() }) }
                    composable("diagnostics") {
                        DiagnosticsScreen(config, connectionState, onBack = { nav.popBackStack() })
                    }
                }
                permPrompt?.let { kind -> PermissionDialog(kind, onAllow = { permissionAllow() }, onLater = { permissionLater() }) }
            }
        }
    }

    private fun updateConfig(transform: (EngineConfig) -> EngineConfig) {
        lifecycleScope.launch { settingsStore.update(transform) }
    }

    private fun updateUi(transform: (UiPrefs) -> UiPrefs) {
        lifecycleScope.launch { settingsStore.updateUi(transform) }
    }

    private fun requestConnect(config: EngineConfig) {
        // Show the tap at once; the service corrects this to Connected/Error when it really knows.
        AetherController.setState(ConnectionState.Connecting)
        if (config.mode == ConnectionMode.PROXY_ONLY) {
            startForegroundService(Intent(this, ProxyOnlyService::class.java).setAction(ProxyOnlyService.ACTION_START))
            return
        }
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingConnect = true
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startForegroundService(Intent(this, AetherVpnService::class.java).setAction(AetherVpnService.ACTION_CONNECT))
        }
    }

    /** Stops the running connection and starts it again with what is saved now. */
    private fun reconnect(config: EngineConfig) {
        lifecycleScope.launch {
            disconnect(config)
            kotlinx.coroutines.withTimeoutOrNull(12_000) {
                AetherController.state.first { it is ConnectionState.Idle || it is ConnectionState.Error }
            }
            requestConnect(settingsStore.configFlow.first())
        }
    }

    private fun disconnect(config: EngineConfig) {
        AetherController.setState(ConnectionState.Disconnecting)
        if (config.mode == ConnectionMode.PROXY_ONLY) {
            startService(Intent(this, ProxyOnlyService::class.java).setAction(ProxyOnlyService.ACTION_STOP))
        } else {
            startService(Intent(this, AetherVpnService::class.java).setAction(AetherVpnService.ACTION_DISCONNECT))
        }
        // Safety net: if the service has not reported back in a few seconds, force-stop both
        // services and return to Idle, so the button can never stay stuck on "Disconnecting".
        lifecycleScope.launch {
            kotlinx.coroutines.delay(6_000)
            if (AetherController.state.value is ConnectionState.Disconnecting) {
                stopService(Intent(this@MainActivity, AetherVpnService::class.java))
                stopService(Intent(this@MainActivity, ProxyOnlyService::class.java))
                AetherController.setState(ConnectionState.Idle)
            }
        }
    }
}
