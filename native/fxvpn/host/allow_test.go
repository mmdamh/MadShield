package main

import "testing"

func TestHostAllowed(t *testing.T) {
	allowed := []string{
		"vpn.mozilla.org", "api.accounts.firefox.com", "accounts.firefox.com", "firefox.settings.services.mozilla.com",
		"product-details.mozilla.org", "ca.m1.fastly-masque.net", "MXP69.M1.Fastly-Masque.NET", "vpn.mozilla.org.",
		"1.1.1.1", "2606:4700:4700::1111", "[2606:4700:4700::1111]", "localhost", "127.0.0.1",
	}
	for _, h := range allowed {
		if !hostAllowed(h) {
			t.Errorf("%q should be allowed", h)
		}
	}
	refused := []string{
		"", " ", "google.com", "connectivitycheck.gstatic.com", "www.msftconnecttest.com", "captive.apple.com", "www.baidu.com",
		"api-ipv4.ip.sb", "raw.githubusercontent.com", "cdn.jsdelivr.net", "github.com", "dns.google",
		"evilmozilla.org", "mozilla.org.evil.com", "fastly-masque.net.evil.com", "xfirefox.com", "mozilla.org@evil.com",
		"firefox.com:443", "vpn.mozilla.org/evil", "a.b.c.d",
	}
	for _, h := range refused {
		if hostAllowed(h) {
			t.Errorf("%q should be refused", h)
		}
	}
	if hostGuard("vpn.mozilla.org") != nil || hostGuard("raw.githubusercontent.com") == nil {
		t.Error("hostGuard must follow hostAllowed")
	}
}

func TestLoopbackProxy(t *testing.T) {
	good := map[string]string{
		"127.0.0.1:1819":    "127.0.0.1:1819",
		" 127.0.0.1:10808 ": "127.0.0.1:10808",
		"localhost:1080":    "localhost:1080",
		"LOCALHOST:1080":    "localhost:1080",
		"[::1]:1080":        "[::1]:1080",
		"127.5.5.5:65535":   "127.5.5.5:65535",
	}
	for in, want := range good {
		if got := loopbackProxy(in); got != want {
			t.Errorf("loopbackProxy(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:abc", "8.8.8.8:1080", "192.168.1.5:1080",
		"example.com:1080", "0.0.0.0:1080", "socks5://127.0.0.1:1080", "127.0.0.1.evil.com:1080", ":1080"} {
		if got := loopbackProxy(in); got != "" {
			t.Errorf("loopbackProxy(%q) = %q, want it refused", in, got)
		}
	}
}
