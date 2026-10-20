package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/theesfeld/airc/internal/boot"
	"github.com/theesfeld/airc/internal/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "airc: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("airc "+cmd, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "airc.yaml", "configuration file")
	name := fs.String("name", "irc.localhost", "server name used on first init")
	listen := fs.String("listen", ":6697", "TLS listen address used on first init")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch cmd {
	case "run":
		return boot.Run(*configPath, *name, *listen, nil)
	case "init":
		password, err := boot.Init(*configPath, *name, *listen)
		if errors.Is(err, boot.ErrInitialized) {
			return fmt.Errorf("%s already exists", *configPath)
		}
		if err != nil {
			return err
		}
		fmt.Printf("admin account: admin\nadmin password: %s\nThis password is shown once. Store it now.\n", password)
		return nil
	case "reset-password":
		if fs.NArg() != 1 {
			return errors.New("usage: airc reset-password [-config airc.yaml] <account>")
		}
		password, err := boot.ResetPassword(*configPath, fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Printf("account: %s\npassword: %s\nThis password is shown once. Store it now.\n", strings.ToLower(fs.Arg(0)), password)
		return nil
	case "version":
		fmt.Println(server.Version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprintf(os.Stderr, "Usage:\n  airc [run] [-config airc.yaml]\n  airc init [-config airc.yaml] [-name irc.example.com] [-listen :6697]\n  airc reset-password [-config airc.yaml] <account>\n  airc version\n")
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}
