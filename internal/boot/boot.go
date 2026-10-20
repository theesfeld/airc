// Package boot creates the on-disk state and starts the server.
package boot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theesfeld/airc/internal/config"
	"github.com/theesfeld/airc/internal/sasl"
	"github.com/theesfeld/airc/internal/store"
)

// ErrInitialized means init was asked to create a server that already has accounts.
var ErrInitialized = errors.New("boot: configuration already exists")

// Init writes a new configuration, certificate, encryption key, and admin account.
func Init(path, name, listen string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", ErrInitialized
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		// Dir of "airc.yaml" is "." which exists.
		if filepath.Dir(path) != "." {
			return "", err
		}
	}
	if err := os.WriteFile(path, []byte(config.Template(name, listen, "data")), 0o600); err != nil {
		return "", err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(cfg.Data.Directory, 0o700); err != nil {
		return "", err
	}
	if _, err := ensureKey(filepath.Join(cfg.Data.Directory, "secret.key")); err != nil {
		return "", err
	}
	if err := ensureCert(cfg.Server.Cert, cfg.Server.Key, []string{cfg.Server.Name, "localhost"}); err != nil {
		return "", err
	}
	st, err := store.Open(filepath.Join(cfg.Data.Directory, "airc.db"))
	if err != nil {
		return "", err
	}
	defer func() { _ = st.Close() }()
	n, err := st.UserCount()
	if err != nil {
		return "", err
	}
	if n > 0 {
		return "", nil
	}
	password, err := Password()
	if err != nil {
		return "", err
	}
	creds, err := sasl.NewCredentials(password, cfg.Limits.SCRAMIterations)
	if err != nil {
		return "", err
	}
	if err := st.CreateUser("admin", "admin", creds); err != nil {
		return "", err
	}
	return password, nil
}

// Open loads an existing configuration and its database.
func Open(path string) (*config.File, *store.Store, []byte, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := os.MkdirAll(cfg.Data.Directory, 0o700); err != nil {
		return nil, nil, nil, err
	}
	key, err := ensureKey(filepath.Join(cfg.Data.Directory, "secret.key"))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := ensureCert(cfg.Server.Cert, cfg.Server.Key, []string{cfg.Server.Name, "localhost"}); err != nil {
		return nil, nil, nil, err
	}
	st, err := store.Open(filepath.Join(cfg.Data.Directory, "airc.db"))
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, st, key, nil
}

// ResetPassword sets a new random SASL password for an account.
func ResetPassword(path, account string) (string, error) {
	_, st, _, err := Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = st.Close() }()
	account = strings.ToLower(account)
	if _, err := st.UserByName(account); err != nil {
		return "", err
	}
	password, err := Password()
	if err != nil {
		return "", err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return "", err
	}
	creds, err := sasl.NewCredentials(password, cfg.Limits.SCRAMIterations)
	if err != nil {
		return "", err
	}
	if err := st.SetPassword(account, creds); err != nil {
		return "", err
	}
	return password, nil
}

// Password returns a one-time account password.
func Password() (string, error) {
	raw := make([]byte, 15)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}

// Fingerprint returns the SHA-256 fingerprint of the certificate.
func Fingerprint(certPath string) (string, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("boot: certificate PEM is empty")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	hexed := hex.EncodeToString(sum[:])
	var parts []string
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return strings.ToUpper(strings.Join(parts, ":")), nil
}

func ensureKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) != 32 {
			return nil, fmt.Errorf("boot: %s is not a 32-byte key", path)
		}
		return raw, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func ensureCert(certPath, keyPath string, dnsNames []string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0], Organization: []string{"aIRC"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPEMPath(certPath), certPEM, 0o644)
}

func certPEMPath(path string) string { return path }
