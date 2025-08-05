package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/k8shell-io/ssh-proxy/internal/log"
	"github.com/k8shell-io/ssh-proxy/internal/server"
)

var (
	SSHPROXY_VERSION = "0.0.0"
	SSHPROXY_COMMIT  = "0000000"
)

// Options represents the command line options
type Options struct {
	ConfigPath         string
	LogText            bool
	ShowVersion        bool
	HandleConnectionFD int  // File descriptor for subprocess mode
	EnableForking      bool // Enable subprocess-based connection handling
}

// getOptions parses the command line options and returns the Options struct
func getOptions(version string, commit_id string) (*Options, error) {
	// Default options
	options := &Options{
		ConfigPath:         "config/config.yaml",
		LogText:            false,
		ShowVersion:        false,
		HandleConnectionFD: -1,
		EnableForking:      false,
	}

	// Parse command line flags
	flag.StringVar(&options.ConfigPath, "config", options.ConfigPath, "Path to the configuration file")
	flag.BoolVar(&options.LogText, "logtext", options.LogText, "Log in text format (default: JSON)")
	flag.BoolVar(&options.ShowVersion, "v", false, "Show version information")
	flag.IntVar(&options.HandleConnectionFD, "fd", -1, "Handle connection from file descriptor")
	flag.BoolVar(&options.EnableForking, "fork", false, "Enable subprocess-based connection handling")

	// Print usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  ssh-proxy [options]\n")
		fmt.Fprint(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprint(os.Stderr, "  --config <file>  Configuration file\n")
		fmt.Fprint(os.Stderr, "  --logtext        Log in text format (default: JSON)\n")
		fmt.Fprint(os.Stderr, "  --fork           Enable subprocess-based connection handling\n")
		fmt.Fprint(os.Stderr, "  --fd <fd>        Handle connection from file descriptor (internal)\n")
		fmt.Fprint(os.Stderr, "  -v               Show version and exit\n")
	}

	// Parse the flags
	flag.Parse()
	if options.ShowVersion {
		fmt.Printf("ssh-proxy version: %s (commit: %s)\n", version, commit_id)
		os.Exit(0)
	}

	return options, nil
}

func main() {
	opts, err := getOptions(SSHPROXY_VERSION, SSHPROXY_COMMIT)
	if err != nil {
		fmt.Printf("Error parsing options: %v\n", err)
		os.Exit(1)
	}

	log.JsonLogger = !opts.LogText
	logger := log.NewLogger("ssh-proxy")

	// Handle subprocess mode for connection handling
	if opts.HandleConnectionFD >= 0 {
		err := server.HandleConnectionFromFD(opts.HandleConnectionFD, opts.ConfigPath)
		if err != nil {
			logger.Error().Msgf("Error handling connection from FD: %v", err)
			os.Exit(1)
		}
		return
	}

	// Normal server mode
	sshServer, err := server.NewServer(opts.ConfigPath)
	if err != nil {
		logger.Error().Msgf("Error starting ssh-proxy: %v", err)
		os.Exit(1)
	}

	// Enable forking if requested
	if opts.EnableForking {
		sshServer.EnableForking()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info().Msg("SSH proxy server started, waiting for connections...")

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info().Msg("Shutting down SSH proxy server...")
	sshServer.Stop()
}
