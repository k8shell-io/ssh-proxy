package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/k8shell-io/common/logger"
	"github.com/k8shell-io/ssh-proxy/internal/server"
)

// Options represents the command line options
type Options struct {
	ConfigPath  string
	LogText     bool
	ShowVersion bool
	IsChild     bool
}

// getOptions parses the command line options and returns the Options struct
func getOptions(version string, commit_id string) (*Options, error) {
	options := &Options{
		ConfigPath:  "config/config.yaml",
		LogText:     false,
		ShowVersion: false,
		IsChild:     false,
	}

	flag.StringVar(&options.ConfigPath, "config", options.ConfigPath, "Path to the configuration file")
	flag.BoolVar(&options.LogText, "logtext", options.LogText, "Log in text format (default: JSON)")
	flag.BoolVar(&options.ShowVersion, "v", false, "Show version information")
	flag.BoolVar(&options.IsChild, "child", false, "Enable child process mode")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  ssh-proxy [options]\n")
		fmt.Fprint(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprint(os.Stderr, "  --config <file>  Configuration file\n")
		fmt.Fprint(os.Stderr, "  --logtext        Log in text format (default: JSON)\n")
		fmt.Fprint(os.Stderr, "  -v               Show version and exit\n")
	}

	flag.Parse()
	if options.ShowVersion {
		fmt.Printf("ssh-proxy version: %s (commit: %s)\n", version, commit_id)
		os.Exit(0)
	}

	return options, nil
}

// main is the entry point for the SSH proxy server
func main() {
	opts, err := getOptions(server.SSHPROXY_VERSION, server.SSHPROXY_COMMIT)
	if err != nil {
		fmt.Printf("Error parsing options: %v\n", err)
		os.Exit(1)
	}

	log.JsonLogger = !opts.LogText
	logger := log.NewLogger("ssh-proxy")

	if opts.IsChild {
		err = server.HandleConnectionChildProcess(opts.ConfigPath)
		if err != nil {
			logger.Error().Msgf("Error handling connection in the child process: %v", err)
			os.Exit(1)
		}
		return
	}

	srv, err := server.NewServer(opts.ConfigPath)
	if err != nil {
		logger.Error().Msgf("Failed to create server: %v", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		logger.Error().Msgf("Failed to start server: %v", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	logger.Info().Msg("Received shutdown signal, stopping server...")

	srv.Stop()
}
