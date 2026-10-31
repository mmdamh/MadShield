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
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBars
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.madshield.app.core.*
import com.madshield.app.ui.*
import com.madshield.app.ui.components.FloatingNavBar
import com.madshield.app.ui.components.Tab
import com.madshield.app.ui.theme.MadShieldTheme
import com.madshield.app.ui.theme.DarkMode
import com.madshield.app.ui.theme.UiPrefs
import com.madshield.app.vpn.AetherVpnService
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

    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(com.madshield.app.core.AppLanguage.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settingsStore = SettingsStore(this)

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

                NavHost(nav, startDestination = "main") {
                    composable("main") {
                        val top = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
                        val padding = PaddingValues(top = top)
                        Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
                            Crossfade(tab, label = "tabs") { current ->
                                when (current) {
                                    Tab.Home -> HomeScreen(
                                        config = config,
                                        connectionState = connectionState,
                                        onSetMode = { m -> updateConfig { it.copy(mode = m) } },
                                        onUpdate = { t -> updateConfig(t) },
                                        onConnect = { requestConnect(config) },
                                        onDisconnect = { disconnect(config) },
                                        onOpenLog = { nav.navigate("log") },
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
                                        contentPadding = padding
                                    )
                                }
                            }
                            Box(Modifier.align(Alignment.BottomCenter)) {
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
                    composable("diagnostics") {
                        DiagnosticsScreen(config, connectionState, onBack = { nav.popBackStack() })
                    }
                }
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
