package config

import (
	"fmt"

	"github.com/k8shell-io/yaml-config/pkg/yamlconfig"
)

// Config represents the server configuration
type Config struct {
	Ssh      SshConfig      `yaml:"ssh"`
	Identity IdentityConfig `yaml:"identity"`
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
