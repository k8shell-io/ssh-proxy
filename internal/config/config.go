package config

import (
	"fmt"
	"os"

	"github.com/k8shell-io/yaml-config/pkg/yamlconfig"
	"golang.org/x/crypto/ssh"
)

// Config represents the server configuration
type Config struct {
	Ssh         SshConfig         `yaml:"ssh"`
	Identity    IdentityConfig    `yaml:"identity"`
	Provisioner ProvisionerConfig `yaml:"provisioner"`
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

type ProvisionerConfig struct {
	BaseURL string `yaml:"baseURL"`
	APIKey  string `yaml:"APIKey"`
	Timeout int    `yaml:"timeout"`
}

// NewConfig creates a new Config instance by loading the configuration from the specified file.
func NewConfig(configFile string) (*Config, error) {
	var config Config

	processor := yamlconfig.NewDefaultProcessor()
	if err := processor.LoadAndDecode(configFile, &config); err != nil {
		return nil, fmt.Errorf("failed to load configuration from '%s': %w", configFile, err)
	}

	if config.Ssh.Port == 0 || config.Identity.APIKey == "" {
		return nil, fmt.Errorf("missing required configuration values: port and APIKey must be set")
	}

	return &config, nil
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
