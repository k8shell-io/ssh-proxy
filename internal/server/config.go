// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"fmt"
	"os"

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

// RecordingConfig controls which SSH channel types are recorded.
// Recording requires the session client to be configured and enabled.
type RecordingConfig struct {
	RecordShell       bool `yaml:"recordShell"`
	RecordExec        bool `yaml:"recordExec"`
	RecordSFTP        bool `yaml:"recordSFTP"`
	RecordDirectTCPIP bool `yaml:"recordDirectTCPIP"`
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
