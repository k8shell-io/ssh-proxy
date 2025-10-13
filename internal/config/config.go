// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package config

import (
	"fmt"
	"os"

	"github.com/k8shell-io/common/pkg/apiclient"
	"github.com/k8shell-io/common/pkg/config"
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/ssh-proxy/internal/nats"
	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"golang.org/x/crypto/ssh"
)

// Config represents the server configuration
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Ssh         SshConfig         `yaml:"ssh"`
	Identity    apiclient.Config  `yaml:"identity"`
	Session     gapi.ClientConfig `yaml:"session"`
	Provisioner apiclient.Config  `yaml:"provisioner"`
	Nats        nats.Config       `yaml:"nats"`
}

// ServerConfig represents the SSH server configuration.
type ServerConfig struct {
	Forking                   bool                        `yaml:"forking"`
	ProxyProtocol             bool                        `yaml:"proxyProtocol"`
	SSHHandshakeTimeout       int                         `yaml:"SSHHandshakeTimeout"`
	MaxDirectTCPIPConnections int                         `yaml:"maxDirectTCPIPConnections"`
	WriterOptions             workspace.InfoWriterOptions `yaml:"writerOptions"`
	SftpBinary                string                      `yaml:"sftpBinary"`
}

// SshConfig represents the SSH server configuration.
type SshConfig struct {
	Port      int    `yaml:"port"`
	ServerKey string `yaml:"serverKey"`
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

	if cfg.Ssh.Port == 0 || cfg.Identity.APIKey == "" {
		return nil, fmt.Errorf("missing required configuration values: port and APIKey must be set")
	}

	return &cfg, nil
}

// GetServerKey loads and returns the SSH server private key as an ssh.Signer
func (c *Config) GetServerKey() (ssh.Signer, error) {
	if c.Ssh.ServerKey == "" {
		return nil, fmt.Errorf("server key path not configured")
	}

	privateKeyBytes, err := os.ReadFile(c.Ssh.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key file '%s': %w", c.Ssh.ServerKey, err)
	}

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key from '%s': %w", c.Ssh.ServerKey, err)
	}

	return signer, nil
}
