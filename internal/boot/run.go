package boot

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/theesfeld/airc/internal/server"
)

// Run starts the server. When the config file is missing, Run initializes it first.
func Run(path, name, listen string, logger *slog.Logger) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		password, err := Init(path, name, listen)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "aIRC initialized\n  config: %s\n  admin account: admin\n  admin password: %s\nThis password is shown once. Store it now.\n\n", path, password)
	} else if err != nil {
		return err
	}
	cfg, st, key, err := Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	srv, err := server.New(cfg, st, nil, key, logger)
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	fp, err := Fingerprint(cfg.Server.Cert)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "aIRC listening on %s as %s\nTLS certificate SHA-256: %s\n", srv.Addr().String(), cfg.Server.Name, fp)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stdout, "aIRC stopping")
	return nil
}
