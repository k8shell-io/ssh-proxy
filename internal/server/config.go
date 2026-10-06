// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"fmt"
	"os"

	"github.com/k8shell-io/common/pkg/api/client/k8shelld"
	sessionv1 "github.com/k8shell-io/common/pkg/api/gen/go/session/v1"
	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/config"
	"github.com/k8shell-io/common/pkg/gapi"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"golang.org/x/crypto/ssh"
)

// Config represents the server configuration
type Config struct {
	Server      ServerConfig           `yaml:"server"`
	Grpc        gapi.ServerConfig      `yaml:"grpc"`
	Nats        natsc.NATSClientConfig `yaml:"nats"`
	Identity    gapi.ClientConfig      `yaml:"identity"`
	Session     gapi.ClientConfig      `yaml:"session"`
	Provisioner gapi.ClientConfig      `yaml:"provisioner"`
	K8shelld    gapi.ClientConfig      `yaml:"k8shelld"`
	Authz       gapi.ClientConfig      `yaml:"authz"`
}

// GrpcEnabled reports whether the gRPC control interface should be started.
// It is opt-in: the server runs only when a port is configured under `grpc`.
func (c *Config) GrpcEnabled() bool {
	return c.Grpc.Port != 0
}

// ServerConfig represents the SSH server configuration.
type ServerConfig struct {
	Port                      int                         `yaml:"port"`
	ServerKey                 string                      `yaml:"serverKey"`
	Forking                   bool                        `yaml:"forking"`
	ProxyProtocol             bool                        `yaml:"proxyProtocol"`
	SSHHandshakeTimeout       int                         `yaml:"SSHHandshakeTimeout"`
	MaxDirectTCPIPConnections int                         `yaml:"maxDirectTCPIPConnections"`
	WriterOptions             workspace.InfoWriterOptions `yaml:"writerOptions"`
	SftpBinary                string                      `yaml:"sftpBinary"`
	PublishSshFailures        PublishSshFailuresConfig    `yaml:"publishSshFailures"`
	Recording                 RecordingConfig             `yaml:"recording"`
}

// PublishSshFailuresConfig represents the configuration for SSH failure reporting
// This requires NATS to be configured.
type PublishSshFailuresConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Subject      string   `yaml:"subject"`
	PublicIPOnly bool     `yaml:"publicIPOnly"`
	Whitelist    []string `yaml:"whitelist"`
}

// RecordingConfig controls which SSH channel types are recorded and how.
// Recording requires the session client to be configured and enabled.
// The Record* flags are the defaults that a session:record authz obligation
// overrides per session; the per-stream options always apply.
type RecordingConfig struct {
	RecordShell       bool `yaml:"recordShell"`
	RecordExec        bool `yaml:"recordExec"`
	RecordSFTP        bool `yaml:"recordSFTP"`
	RecordDirectTCPIP bool `yaml:"recordDirectTCPIP"`

	// BufferBytes limits the data each recording queues while it waits to be
	// sent to the session service; data beyond it is dropped and reported as
	// a gap. 0 selects the k8shelld client default (8 MiB).
	BufferBytes int `yaml:"bufferBytes"`

	// Per-stream recording options sent in each recording header. Unset
	// fields fall back to the session service's defaults.
	Shell       StreamRecordingOptions `yaml:"shell"`
	Exec        StreamRecordingOptions `yaml:"exec"`
	SFTP        StreamRecordingOptions `yaml:"sftp"`
	DirectTCPIP StreamRecordingOptions `yaml:"directTCPIP"`
}

// StreamRecordingOptions is the recording setup for one stream type
// (session.v1.RecordingOptions).
type StreamRecordingOptions struct {
	// Format is the file format of the stream's raw data: asciinema, pcapng
	// or none. Empty uses the session service's format for the stream type.
	// none is only valid for directTCPIP with vscode.terminals enabled, and
	// stores only the VS Code terminal recordings.
	Format string `yaml:"format"`
	// Gzip stores asciinema files gzip-compressed. Unset uses the service default.
	Gzip *bool `yaml:"gzip"`
	// Vscode configures VS Code terminal capture; only valid for directTCPIP.
	Vscode VscodeRecordingOptions `yaml:"vscode"`
}

// VscodeRecordingOptions configures recording of VS Code integrated
// terminals carried by a port-forward (session.v1.VscodeRecordingOptions).
type VscodeRecordingOptions struct {
	// Terminals records each VS Code integrated terminal as its own asciinema
	// recording. Unset uses the service default.
	Terminals *bool `yaml:"terminals"`
	// RecordInput includes terminal keystrokes in those recordings. Unset
	// uses the service default.
	RecordInput *bool `yaml:"recordInput"`
}

var recordingFormats = map[string]sessionv1.RecordingFormat{
	"":          sessionv1.RecordingFormat_RECORDING_FORMAT_UNSPECIFIED,
	"asciinema": sessionv1.RecordingFormat_RECORDING_FORMAT_ASCIINEMA,
	"pcapng":    sessionv1.RecordingFormat_RECORDING_FORMAT_PCAPNG,
	"none":      sessionv1.RecordingFormat_RECORDING_FORMAT_NONE,
}

// validate checks the options of the stream named name; tcpip reports
// whether it is the direct-tcpip stream, the only one with VS Code options.
func (o StreamRecordingOptions) validate(name string, tcpip bool) error {
	format, ok := recordingFormats[o.Format]
	if !ok {
		return fmt.Errorf("recording.%s.format: unknown format %q (want asciinema, pcapng or none)", name, o.Format)
	}
	vscodeSet := o.Vscode.Terminals != nil || o.Vscode.RecordInput != nil
	if !tcpip && vscodeSet {
		return fmt.Errorf("recording.%s.vscode: VS Code options are only valid for directTCPIP", name)
	}
	if format == sessionv1.RecordingFormat_RECORDING_FORMAT_NONE &&
		(!tcpip || o.Vscode.Terminals == nil || !*o.Vscode.Terminals) {
		return fmt.Errorf("recording.%s.format: none is only valid for directTCPIP with vscode.terminals enabled", name)
	}
	return nil
}

// proto returns the options as sent in a recording header, or nil when
// nothing is set so the session service applies all of its defaults.
func (o StreamRecordingOptions) proto() *sessionv1.RecordingOptions {
	if o.Format == "" && o.Gzip == nil && o.Vscode.Terminals == nil && o.Vscode.RecordInput == nil {
		return nil
	}
	ro := &sessionv1.RecordingOptions{Format: recordingFormats[o.Format], Gzip: o.Gzip}
	if o.Vscode.Terminals != nil || o.Vscode.RecordInput != nil {
		ro.Vscode = &sessionv1.VscodeRecordingOptions{
			Terminals:   o.Vscode.Terminals,
			RecordInput: o.Vscode.RecordInput,
		}
	}
	return ro
}

// validate checks every stream's options.
func (c RecordingConfig) validate() error {
	if c.BufferBytes < 0 {
		return fmt.Errorf("recording.bufferBytes must not be negative")
	}
	for _, s := range []struct {
		name  string
		opts  StreamRecordingOptions
		tcpip bool
	}{
		{"shell", c.Shell, false},
		{"exec", c.Exec, false},
		{"sftp", c.SFTP, false},
		{"directTCPIP", c.DirectTCPIP, true},
	} {
		if err := s.opts.validate(s.name, s.tcpip); err != nil {
			return err
		}
	}
	return nil
}

// K8shelld returns the recording setup applied by the k8shelld client.
func (c RecordingConfig) K8shelld() k8shelld.RecordingConfig {
	return k8shelld.RecordingConfig{
		BufferBytes: c.BufferBytes,
		Shell:       c.Shell.proto(),
		Exec:        c.Exec.proto(),
		Sftp:        c.SFTP.proto(),
		Tcpip:       c.DirectTCPIP.proto(),
	}
}

const (
	// DefaultSSHHandshakeTimeout is the default timeout for SSH handshakes.
	DEFAULT_SSH_HANDSHAKE_TIMEOUT = 30

	// DefaultMaxDirectTCPIPConnections is the default maximum number of direct TCP/IP connections
	DEFAULT_MAX_DIRECT_TCPIP_CONNECTIONS = 15

	// DefaultSftpBinary is the default path to the SFTP binary
	DEFAULT_SFTP_BINARY = "/usr/local/bin/sftp"
)

// NewConfig creates a new Config instance by loading the configuration from the specified file.
func NewConfig(configFile string) (*Config, error) {
	var cfg Config

	processor := config.NewDefaultProcessor()
	if err := processor.LoadAndDecode(configFile, &cfg); err != nil {
		return nil, fmt.Errorf("failed to load configuration from '%s': %w", configFile, err)
	}

	if cfg.Server.SSHHandshakeTimeout == 0 {
		cfg.Server.SSHHandshakeTimeout = DEFAULT_SSH_HANDSHAKE_TIMEOUT
	}

	if cfg.Server.MaxDirectTCPIPConnections == 0 {
		cfg.Server.MaxDirectTCPIPConnections = DEFAULT_MAX_DIRECT_TCPIP_CONNECTIONS
	}

	if cfg.Server.SftpBinary == "" {
		cfg.Server.SftpBinary = DEFAULT_SFTP_BINARY
	}

	if cfg.Server.Port == 0 {
		return nil, fmt.Errorf("missing required configuration values: port must be set")
	}

	// TODO: temporary default until deployed configs set it — capture VS Code
	// terminals (with keystrokes) in port-forwards unless configured otherwise.
	// Only with a session service: recording without one fails the channel.
	if cfg.Session.Address != "" {
		vscode := &cfg.Server.Recording.DirectTCPIP.Vscode
		if vscode.Terminals == nil {
			vscode.Terminals = boolPtr(true)
		}
		if vscode.RecordInput == nil {
			vscode.RecordInput = boolPtr(true)
		}
	}

	if err := cfg.Server.Recording.validate(); err != nil {
		return nil, fmt.Errorf("invalid server configuration: %w", err)
	}

	return &cfg, nil
}

// GetServerKey loads and returns the SSH server private key as an ssh.Signer
func (c *Config) GetServerKey() (ssh.Signer, error) {
	if c.Server.ServerKey == "" {
		return nil, fmt.Errorf("server key path not configured")
	}

	privateKeyBytes, err := os.ReadFile(c.Server.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key file '%s': %w", c.Server.ServerKey, err)
	}

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key from '%s': %w", c.Server.ServerKey, err)
	}

	return signer, nil
}

func boolPtr(b bool) *bool { return &b }

// tcpipRecording decides whether a direct-tcpip channel is recorded and with
// which options. ob is the session:record obligation, or nil when there is
// none and the static config decides. The channel is recorded for its raw
// data (direct-tcpip / recordDirectTCPIP), for the VS Code terminals it
// carries (vscode-terminals / vscode.terminals), or both; with terminals only,
// the format is none so no pcap-ng is stored.
func (c RecordingConfig) tcpipRecording(ob *authz.RecordObligation) (bool, *sessionv1.RecordingOptions) {
	opts := c.DirectTCPIP.proto()
	if opts == nil {
		opts = &sessionv1.RecordingOptions{}
	}
	if opts.Vscode == nil {
		opts.Vscode = &sessionv1.VscodeRecordingOptions{}
	}

	rawData := c.RecordDirectTCPIP
	terminals := opts.Vscode.Terminals != nil && *opts.Vscode.Terminals
	if ob != nil {
		rawData, terminals = ob.DirectTCPIP, ob.VscodeTerminals
		opts.Vscode.Terminals = boolPtr(ob.VscodeTerminals)
		opts.Vscode.RecordInput = boolPtr(ob.VscodeInput)
	}

	switch {
	case !rawData && !terminals:
		return false, nil
	case !rawData:
		opts.Format = sessionv1.RecordingFormat_RECORDING_FORMAT_NONE
	case opts.Format == sessionv1.RecordingFormat_RECORDING_FORMAT_NONE:
		// The policy asks for the raw data the static config would not store.
		opts.Format = sessionv1.RecordingFormat_RECORDING_FORMAT_UNSPECIFIED
	}
	return true, opts
}
