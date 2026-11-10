package main

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
)

// The user's own Guardian relay (a Cloudflare Worker they deploy themselves, see tools/guardian-relay in the MadShield
// source). Mozilla's VPN service refuses some regions by the address a request comes from; the relay makes the account
// and pass requests to Guardian (and only those) from its own address. It sees the account's access token on the way,
// which is why there is no default and no shared one: the app sends it only when the user typed their own address.

// relayHost is the one extra name hostAllowed lets through: the exact host of the relay, never a wildcard.
var relayHost atomic.Value // string

// parseRelay checks the relay address from MFX_GUARDIAN_RELAY and returns it without a trailing slash: https only, a
// name (not an address), no login, query or fragment. A path is allowed: the Worker's secret is its first part.
func parseRelay(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.New("the relay must be an https address")
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if h == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("the relay address needs a host and nothing else but a path")
	}
	if _, perr := netip.ParseAddr(h); perr == nil || h == "localhost" || !strings.Contains(h, ".") {
		return "", errors.New("the relay must be a domain name")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// allowRelay lets the core reach the relay's host (and only it).
func allowRelay(endpoint string) {
	if u, err := url.Parse(endpoint); err == nil {
		relayHost.Store(strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")))
	}
}
