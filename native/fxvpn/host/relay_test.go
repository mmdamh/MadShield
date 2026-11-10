package main

import "testing"

func TestParseRelay(t *testing.T) {
	good := map[string]string{
		"https://mrg.example.workers.dev":     "https://mrg.example.workers.dev",
		"https://mrg.example.workers.dev/":    "https://mrg.example.workers.dev",
		" https://Relay.Example.com/s3cret/ ": "https://Relay.Example.com/s3cret",
		"https://relay.example.com:8443/abc":  "https://relay.example.com:8443/abc",
	}
	for in, want := range good {
		got, err := parseRelay(in)
		if err != nil || got != want {
			t.Errorf("parseRelay(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "http://relay.example.com", "ftp://relay.example.com", "relay.example.com", "https://", "https://1.2.3.4/x",
		"https://[2606:4700::1]/x", "https://localhost/x", "https://intranet/x", "https://u:p@relay.example.com",
		"https://relay.example.com/?a=b", "https://relay.example.com/#x",
	}
	for _, in := range bad {
		if got, err := parseRelay(in); err == nil {
			t.Errorf("parseRelay(%q) = %q; want an error", in, got)
		}
	}
}

func TestRelayHostAllowed(t *testing.T) {
	relayHost.Store("")
	if hostAllowed("mrg.example.workers.dev") {
		t.Fatal("a relay host must be refused until one is set")
	}
	allowRelay("https://mrg.example.workers.dev/secret")
	t.Cleanup(func() { relayHost.Store("") })
	if !hostAllowed("mrg.example.workers.dev") || !hostAllowed("MRG.example.workers.dev.") {
		t.Error("the relay host should be allowed")
	}
	for _, h := range []string{"other.example.workers.dev", "example.workers.dev", "evil.mrg.example.workers.dev", "workers.dev"} {
		if hostAllowed(h) {
			t.Errorf("%q must stay refused: only the exact relay host is allowed", h)
		}
	}
}
