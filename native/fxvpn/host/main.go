// madshield-fx is the small program MadShield runs for its "Firefox VPN" engine. It is built inside the module of
// armanlife/firefox-vpn-client (core/), at the commit in native/fxvpn.pin, because it uses that module's internal
// packages: CI copies this folder to core/cmd/madshield-fx/ and builds it as a static linux/arm64 ELF.
//
// It does what the project's own phone build does (core/mobile/mobile.go), as a separate process instead of a library:
//
//   - the same daemon (service.NewDaemon / Run) with the same dashboard API, but the API answers ONLY a client that
//     sends the local token (RequireLocalToken): every app on the phone can reach 127.0.0.1;
//   - the proxy listens on 127.0.0.1 with a SOCKS5 login that MadShield generates for every start;
//   - settings the app does not offer are forced off whatever the config file says (see applyEnv), so the only
//     network traffic is to Mozilla (Firefox Accounts, the VPN service, the server list and the proxies) and the
//     DNS servers named below;
//   - it ends when its standard input closes (MadShield died), on SIGTERM, or when Run stops.
//
// Settings come from the environment, never from argv (argv is readable by other apps):
//
//	MFX_SOCKS_PORT, MFX_API_PORT   loopback ports
//	MFX_SOCKS_USER, MFX_SOCKS_PASS SOCKS5 login of the proxy
//	MFX_DNS                        optional, comma-separated resolvers for the core's own lookups (see config dns.servers)
//	MFX_HELLO_SPLIT                optional: off, sni, first-byte or record (network.hello_split)
//	MFX_SYSTEM_DNS                 optional, comma-separated IPs of the phone's own DNS servers (plain DNS, port 53): the
//	                               "system" lookups of the core (its fallback when the encrypted resolvers are blocked)
//	                               ask these, because a static Go binary on Android finds no /etc/resolv.conf
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/armanlife/firefox-vpn-client/core/internal/config"
	"github.com/armanlife/firefox-vpn-client/core/internal/guardian"
	"github.com/armanlife/firefox-vpn-client/core/internal/hellosplit"
	"github.com/armanlife/firefox-vpn-client/core/internal/netcheck"
	"github.com/armanlife/firefox-vpn-client/core/internal/resolver"
	"github.com/armanlife/firefox-vpn-client/core/internal/service"
)

// extraRoots: root certificates Mozilla's servers chain to that older Android stores lack (the same file the project's
// own phone build embeds). CI copies it next to this file from core/mobile/extra-roots.pem.
//
//go:embed extra-roots.pem
var extraRoots []byte

const (
	apexCerts   = "/apex/com.android.conscrypt/cacerts"
	systemCerts = "/system/etc/security/cacerts"
)

func main() {
	dataDir := flag.String("data-dir", "", "data folder (required)")
	flag.Parse()
	if strings.TrimSpace(*dataDir) == "" {
		fmt.Fprintln(os.Stderr, "madshield-fx: -data-dir is required")
		os.Exit(2)
	}
	if err := run(*dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "madshield-fx: "+err.Error())
		os.Exit(1)
	}
}

func run(dataDir string) error {
	limitEgress()
	paths, err := service.ResolveDataPaths(dataDir)
	if err != nil {
		return err
	}
	// A token of an earlier run would let the app trust whatever answers on the API port before this run owns it.
	_ = os.Remove(paths.LocalToken)
	if err := useAndroidRoots(paths.Dir); err != nil {
		return err
	}
	useSystemDNS()
	// Passwords an earlier build let the core keep go now (the new core keeps none).
	if n, err := scrubStoredPasswords(paths.Dir); err != nil {
		fmt.Fprintln(os.Stderr, "madshield-fx: removing stored passwords failed: "+err.Error())
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "madshield-fx: removed %d stored account password(s)\n", n)
	}
	if err := applyEnv(paths.Config); err != nil {
		return err
	}
	d, err := service.NewDaemon(paths, false)
	if err != nil {
		return err
	}
	d.RequireLocalToken()
	d.Off() // the proxy stays off until the app presses its button (POST /api/power)

	stop := make(chan struct{}, 2)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		stop <- struct{}{}
	}()
	go func() {
		// MadShield keeps our standard input open; when it ends the app is gone and so are we.
		_, _ = io.Copy(io.Discard, os.Stdin)
		stop <- struct{}{}
	}()
	go func() {
		<-stop
		d.Shutdown()
	}()
	return d.Run()
}

// limitEgress closes every way out of the core that is not Mozilla's (see the patch in native/fxvpn/patches):
//
//   - resolver.HostGuard: only Mozilla's names (allow.go) are looked up or connected to, whatever a setting, the server
//     list or a request to the dashboard asks for;
//   - the connectivity checks the core makes when Mozilla cannot be reached (Google, Microsoft, Apple, Baidu, ip.sb,
//     outside the tunnel, with this phone's real address) are switched off: MadShield does its own network checks;
//   - the account password is not kept on disk: it is used for the sign-in and forgotten.
func limitEgress() {
	resolver.HostGuard = hostGuard
	netcheck.Check = func(context.Context) netcheck.Result { return netcheck.Unknown }
	netcheck.InsideVPN = func(context.Context) bool { return false }
	service.RememberPassword = false
}

// applyEnv writes the settings MadShield owns into config.json (created with the project's defaults when missing),
// only when something changed.
func applyEnv(path string) error {
	socksPort, err := port("MFX_SOCKS_PORT")
	if err != nil {
		return err
	}
	apiPort, err := port("MFX_API_PORT")
	if err != nil {
		return err
	}
	user, pass := os.Getenv("MFX_SOCKS_USER"), os.Getenv("MFX_SOCKS_PASS")
	if user == "" || pass == "" {
		return errors.New("MFX_SOCKS_USER and MFX_SOCKS_PASS are required")
	}
	cfg, _, err := config.Load(path)
	if err != nil {
		return err
	}
	before := cfg

	cfg.Proxy.Listen = "127.0.0.1:" + strconv.Itoa(socksPort)
	cfg.Proxy.Username, cfg.Proxy.Password = user, pass
	cfg.Proxy.IdleSleep = 0 // the phone's VPN is on: keep the session to Mozilla open, as the project's phone build does
	cfg.Proxy.AllowLocked = false
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:" + strconv.Itoa(apiPort)
	cfg.Dashboard.Username, cfg.Dashboard.PasswordHash = "", ""
	// Nothing besides Mozilla: no routing lists downloaded from GitHub (MadShield has its own routing), no relay that
	// would see the tokens, no second proxy in front, no system proxy, no TUN of the core's own.
	cfg.Routing.Enabled = false
	cfg.Network.APIRelay = ""
	cfg.Network.GuardianEndpoint = guardian.DefaultEndpoint // the account's token goes to Mozilla's service only
	cfg.Proxy.Server = ""                                   // the server is chosen from Mozilla's list by country
	cfg.Network.UpstreamProxyEnabled = false
	cfg.Network.UpstreamProxy = ""
	cfg.Network.UpstreamProxyUsername, cfg.Network.UpstreamProxyPassword = "", ""
	cfg.SystemProxy.Mode = config.SystemProxyClear
	cfg.Tun.Programs = []config.TunProgram{}
	if v := strings.TrimSpace(os.Getenv("MFX_DNS")); v != "" {
		var servers []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				servers = append(servers, s)
			}
		}
		cfg.DNS.Servers = servers
	}
	// How the TLS hello of the connections to Mozilla goes out (a network that filters by server name stalls the
	// handshake; splitting the first packet gets past many). Only the core's own choices are accepted.
	if v := strings.TrimSpace(os.Getenv("MFX_HELLO_SPLIT")); v != "" {
		if hellosplit.Valid(v) {
			cfg.Network.HelloSplit = v
		} else {
			fmt.Fprintf(os.Stderr, "[madshield-fx] ignoring MFX_HELLO_SPLIT=%q\n", v)
		}
	}

	if err := cfg.Validate(); err != nil {
		return err
	}
	if reflect.DeepEqual(before, cfg) {
		return nil
	}
	return config.Save(path, cfg)
}

// useSystemDNS makes the system resolver (net.DefaultResolver, used by the core for its "system" lookups) ask the
// phone's DNS servers named in MFX_SYSTEM_DNS. Without it Go reads a missing /etc/resolv.conf and asks 127.0.0.1:53, so on
// a network that blocks DNS over HTTPS (Cloudflare, Google, Quad9 reset or time out) nothing could be resolved.
func useSystemDNS() {
	var servers []string
	for _, s := range strings.Split(os.Getenv("MFX_SYSTEM_DNS"), ",") {
		s = strings.TrimSpace(s)
		if ip, err := netip.ParseAddr(s); err == nil {
			servers = append(servers, net.JoinHostPort(ip.String(), "53"))
		}
	}
	if len(servers) == 0 {
		return
	}
	var turn atomic.Uint32
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Go's resolver retries and falls back to TCP itself; every attempt takes the next server.
			server := servers[int(turn.Add(1)-1)%len(servers)]
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
}

func port(name string) (int, error) {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil || n < 1024 || n > 65535 {
		return 0, fmt.Errorf("%s must be a port number between 1024 and 65535", name)
	}
	return n, nil
}

// useAndroidRoots points Go's certificate verification at the roots Android trusts plus extraRoots. A static Go binary
// on Android finds no system store of its own. Go reads these variables once, at the first verification.
func useAndroidRoots(dataDir string) error {
	file := filepath.Join(dataDir, "extra-roots.pem")
	if err := os.WriteFile(file, extraRoots, 0o600); err != nil {
		return err
	}
	store := systemCerts
	if _, err := os.Stat(apexCerts); err == nil {
		store = apexCerts
	}
	// The system's roots only: a certificate the user (or an app) installed is NOT trusted by this core, so no one holding
	// such a certificate can read the account's traffic to Mozilla.
	if err := os.Setenv("SSL_CERT_DIR", store); err != nil {
		return err
	}
	return os.Setenv("SSL_CERT_FILE", file)
}
