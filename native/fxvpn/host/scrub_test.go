package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeCreds(t *testing.T, root, id, content string) string {
	t.Helper()
	dir := filepath.Join(root, "accounts", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScrubRemovesOldPasswordsAndKeepsTokens(t *testing.T) {
	root := t.TempDir()
	a := writeCreds(t, root, "a1", `{"access_token":"AT","refresh_token":"RT","scope":"s","expires_in":3600,"password":"v1:abcd"}`)
	b := writeCreds(t, root, "b2", `{"access_token":"AT2","refresh_token":"RT2"}`) // already without one
	key := filepath.Join(root, "accounts", "secret.key")
	if err := os.WriteFile(key, []byte("00ff\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := scrubStoredPasswords(root)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var got map[string]any
	data, _ := os.ReadFile(a)
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if _, has := got["password"]; has {
		t.Fatal("password still stored")
	}
	if got["access_token"] != "AT" || got["refresh_token"] != "RT" || got["expires_in"] != float64(3600) {
		t.Fatalf("tokens damaged: %v", got)
	}
	if fi, _ := os.Stat(a); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatal("secret.key must go once no password is left")
	}
	if d, _ := os.ReadFile(b); string(d) != `{"access_token":"AT2","refresh_token":"RT2"}` {
		t.Fatal("a file without a password must not be touched")
	}

	// again: nothing to do, no error
	if n, err := scrubStoredPasswords(root); err != nil || n != 0 {
		t.Fatalf("second run n=%d err=%v", n, err)
	}
}

func TestScrubKeepsKeyWhenAFileCannotBeRead(t *testing.T) {
	root := t.TempDir()
	writeCreds(t, root, "a1", `{"password":"v1:x"}`)
	writeCreds(t, root, "b2", `{not json`)
	key := filepath.Join(root, "accounts", "secret.key")
	_ = os.WriteFile(key, []byte("00ff\n"), 0o600)
	if _, err := scrubStoredPasswords(root); err == nil {
		t.Fatal("a damaged file must be reported")
	}
	if _, err := os.Stat(key); err != nil {
		t.Fatal("the key must stay while a password may still be stored")
	}
}

func TestScrubWithoutAccountsFolder(t *testing.T) {
	if n, err := scrubStoredPasswords(t.TempDir()); n != 0 || err != nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
