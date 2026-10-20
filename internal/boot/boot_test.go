package boot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theesfeld/airc/internal/store"
)

func TestInitOnceAndResetPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "airc.yaml")
	password, err := Init(path, "irc.test", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if len(password) < 12 {
		t.Fatalf("password %q is too short", password)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), password) {
		t.Fatal("config file contains the admin password")
	}
	if _, err := Init(path, "irc.test", "127.0.0.1:0"); !errors.Is(err, ErrInitialized) {
		t.Fatalf("second init err = %v", err)
	}

	cfg, st, key, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length %d", len(key))
	}
	admin, err := st.UserByName("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !admin.Creds.Verify(password) {
		t.Fatal("stored admin password does not verify")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, path)
	assertPrivate(t, filepath.Join(cfg.Data.Directory, "secret.key"))
	assertPrivate(t, filepath.Join(cfg.Data.Directory, "airc.db"))

	next, err := ResetPassword(path, "Admin")
	if err != nil {
		t.Fatal(err)
	}
	if next == password {
		t.Fatal("reset password matched the original")
	}
	st, err = store.Open(filepath.Join(cfg.Data.Directory, "airc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	admin, err = st.UserByName("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !admin.Creds.Verify(next) {
		t.Fatal("reset password does not verify")
	}
	if admin.Creds.Verify(password) {
		t.Fatal("old password still verifies")
	}
	fp, err := Fingerprint(cfg.Server.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(fp, ":")) != 32 {
		t.Fatalf("fingerprint %q", fp)
	}
}

func assertPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("%s mode %o", path, info.Mode().Perm())
	}
}
