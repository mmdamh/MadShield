package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// scrubStoredPasswords removes the Firefox Account password that an earlier MadShield build let the core keep
// (credentials.json "password", encrypted with accounts/secret.key beside it, which is no protection against anyone
// who can read the folder). The core keeps an old password whenever it updates the tokens, so without this an upgrade
// would leave it on the phone for ever. Tokens stay: the account keeps working. Once no password is left, the key that
// only served to encrypt it goes too. It returns how many passwords it removed.
func scrubStoredPasswords(dataDir string) (int, error) {
	dir := filepath.Join(dataDir, "accounts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	var failed error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), "credentials.json")
		data, err := os.ReadFile(path)
		if err != nil {
			continue // an account folder without credentials has nothing to scrub
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			failed = fmt.Errorf("reading %s: %w", path, err)
			continue
		}
		if _, ok := fields["password"]; !ok {
			continue
		}
		delete(fields, "password")
		out, err := json.MarshalIndent(fields, "", "  ")
		if err != nil {
			failed = err
			continue
		}
		if err := writePrivate(path, append(out, '\n')); err != nil {
			failed = err
			continue
		}
		removed++
	}
	if failed != nil {
		return removed, failed // the key stays: a password may still be stored
	}
	if err := os.Remove(filepath.Join(dir, "secret.key")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return removed, err
	}
	return removed, nil
}

// writePrivate replaces path with data through a temporary file in the same folder (0600), so a crash leaves either
// the old file or the new one.
func writePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
