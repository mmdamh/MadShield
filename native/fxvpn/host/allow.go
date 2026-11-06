package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
)

// allowedDomains are the only names the core may look up or connect to. They are what the program needs and nothing
// else: Firefox Accounts (accounts.firefox.com, api.accounts.firefox.com), the VPN service (vpn.mozilla.org), the
// server list (firefox.settings.services.mozilla.com), the Firefox version (product-details.mozilla.org) and Mozilla's
// proxy servers, which are all <name>.m1.fastly-masque.net in the list Mozilla publishes. A name outside these (a
// flag download from GitHub, an update, a routing list, a server the list was changed to name) is refused before any
// lookup or connection is made. IP addresses are not names: the core's DNS servers are addresses, and the addresses of
// the names above come from lookups this guard has already passed.
var allowedDomains = []string{
	"firefox.com",
	"mozilla.org",
	"mozilla.com",
	"mozilla.net",
	"fastly-masque.net",
}

// hostAllowed reports whether name may be looked up or connected to.
func hostAllowed(name string) bool {
	h := strings.ToLower(strings.TrimSpace(name))
	h = strings.TrimSuffix(h, ".")
	h = strings.Trim(h, "[]")
	if h == "" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true // an address, not a name
	}
	if h == "localhost" {
		return true
	}
	for _, d := range allowedDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

var refused sync.Map // names already reported, so the log shows each once

// hostGuard is installed as resolver.HostGuard.
func hostGuard(name string) error {
	if hostAllowed(name) {
		return nil
	}
	if _, seen := refused.LoadOrStore(strings.ToLower(name), true); !seen {
		fmt.Fprintf(os.Stderr, "madshield-fx: refused to contact %q: not a Mozilla host\n", name)
	}
	return fmt.Errorf("madshield: %q is not a Mozilla host; it is not contacted", name)
}
