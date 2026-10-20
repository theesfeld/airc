// Package config loads the aIRC YAML file and fills defaults.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// File is the on-disk server configuration. Secrets are not stored here.
type File struct {
	Server Server `yaml:"server"`
	Data   Data   `yaml:"data"`
	Limits Limits `yaml:"limits"`
}

// Server is the public identity and listen address.
type Server struct {
	Name    string `yaml:"name"`
	Network string `yaml:"network"`
	Listen  string `yaml:"listen"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// Data is where the database, encryption key, and certificates live.
type Data struct {
	Directory string `yaml:"directory"`
}

// Limits are operator-tunable safety bounds.
type Limits struct {
	SCRAMIterations int           `yaml:"scram_iterations"`
	AuthFailures    int           `yaml:"auth_failures"`
	AuthBan         time.Duration `yaml:"auth_ban"`
	Replay          int           `yaml:"replay"`
	ContextMessages int           `yaml:"context_messages"`
	ProviderTimeout time.Duration `yaml:"provider_timeout"`
	MaxConnections  int           `yaml:"max_connections"`
}

// Load reads a config file and resolves relative paths against its directory.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	f.defaults()
	base := filepath.Dir(path)
	f.Data.Directory = abs(base, f.Data.Directory)
	if f.Server.Cert == "" {
		f.Server.Cert = filepath.Join(f.Data.Directory, "tls", "cert.pem")
	} else {
		f.Server.Cert = abs(base, f.Server.Cert)
	}
	if f.Server.Key == "" {
		f.Server.Key = filepath.Join(f.Data.Directory, "tls", "key.pem")
	} else {
		f.Server.Key = abs(base, f.Server.Key)
	}
	return &f, nil
}

func (f *File) defaults() {
	if f.Server.Name == "" {
		f.Server.Name = "irc.localhost"
	}
	if f.Server.Network == "" {
		f.Server.Network = "aIRC"
	}
	if f.Server.Listen == "" {
		f.Server.Listen = ":6697"
	}
	if f.Data.Directory == "" {
		f.Data.Directory = "data"
	}
	if f.Limits.SCRAMIterations == 0 {
		f.Limits.SCRAMIterations = 600_000
	}
	if f.Limits.AuthFailures == 0 {
		f.Limits.AuthFailures = 5
	}
	if f.Limits.AuthBan == 0 {
		f.Limits.AuthBan = 10 * time.Minute
	}
	if f.Limits.Replay == 0 {
		f.Limits.Replay = 100
	}
	if f.Limits.ContextMessages == 0 {
		f.Limits.ContextMessages = 40
	}
	if f.Limits.ProviderTimeout == 0 {
		f.Limits.ProviderTimeout = 180 * time.Second
	}
	if f.Limits.MaxConnections == 0 {
		f.Limits.MaxConnections = 1000
	}
}

func abs(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// Template is the config written on first run.
func Template(name, listen, dataDir string) string {
	return fmt.Sprintf(`# aIRC configuration. Account passwords and provider keys are not stored here.
server:
  name: %s
  network: aIRC
  listen: %q

data:
  # Database, encryption key, and TLS certificate.
  directory: %s

limits:
  # PBKDF2-HMAC-SHA256 iterations for SASL SCRAM-SHA-256 and PLAIN.
  scram_iterations: 600000
  auth_failures: 5
  auth_ban: 10m
  replay: 100
  context_messages: 40
  provider_timeout: 180s
  max_connections: 1000
`, name, listen, dataDir)
}
