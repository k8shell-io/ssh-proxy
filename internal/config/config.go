package config

import (
	"fmt"
	"os"

	"github.com/k8shell-io/common/config"
	"github.com/k8shell-io/ssh-proxy/internal/nats"
	"golang.org/x/crypto/ssh"
)

// Config represents the server configuration
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Ssh         SshConfig         `yaml:"ssh"`
	Identity    IdentityConfig    `yaml:"identity"`
	Provisioner ProvisionerConfig `yaml:"provisioner"`
	Nats        nats.Config       `yaml:"nats"`
}

type ServerConfig struct {
	Forking                   bool `yaml:"forking"`
	ProxyProtocol             bool `yaml:"proxyProtocol"`
	ShowProvisionInfo         bool `yaml:"showProvisionInfo"`
	SSHHandshakeTimeout       int  `yaml:"SSHHandshakeTimeout"`
	MaxDirectTCPIPConnections int  `yaml:"maxDirectTCPIPConnections"`
}

// SshConfig represents the SSH server configuration.
type SshConfig struct {
	Port      int    `yaml:"port"`
	ServerKey string `yaml:"serverKey"`
}

// IdentityConfig represents the identity service configuration.
type IdentityConfig struct {
	BaseURL string `yaml:"baseURL"`
	APIKey  string `yaml:"APIKey"`
	Timeout int    `yaml:"timeout"`
}

// ProvisionerConfig represents the provisioner service configuration.
type ProvisionerConfig struct {
	BaseURL string `yaml:"baseURL"`
	APIKey  string `yaml:"APIKey"`
	Timeout int    `yaml:"timeout"`
}

const (
	DEFAULT_SSH_HANDSHAKE_TIMEOUT        = 30
	DEFAULT_MAX_DIRECT_TCPIP_CONNECTIONS = 15
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

	if cfg.Ssh.Port == 0 || cfg.Identity.APIKey == "" {
		return nil, fmt.Errorf("missing required configuration values: port and APIKey must be set")
	}

	return &cfg, nil
}

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
