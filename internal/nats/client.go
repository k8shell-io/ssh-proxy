package nats

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/nats-io/nats.go"
)

// NatsConfig represents the NATS messaging service configuration.
type Config struct {
	Host        string            `yaml:"host"`
	Port        int               `yaml:"port"`
	User        string            `yaml:"user"`
	Password    string            `yaml:"password"`
	SshFailures SshFailuresConfig `yaml:"sshFailures"`
}

type SshFailuresConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Subject      string   `yaml:"subject"`
	PublicIPOnly bool     `yaml:"publicIPOnly"`
	Whitelist    []string `yaml:"whitelist"`
}

type Client struct {
	config    Config
	conn      *nats.Conn
	proxyId   string
	whitelist []*net.IPNet
}

// FailedConnectionEvent represents a failed SSH connection attempt
type FailedConnectionEvent struct {
	ClientIP    string   `json:"client_ip"`
	ClientPort  int      `json:"client_port"`
	Username    string   `json:"username"`
	Timestamp   string   `json:"timestamp"`
	FailureInfo []string `json:"failure_info"`
	ProxyID     string   `json:"proxy_id"`
}

func NewClient(config Config, proxyId string) (*Client, error) {
	url := fmt.Sprintf("nats://%s:%d", config.Host, config.Port)

	opts := []nats.Option{
		nats.Name("ssh-proxy"),
		nats.Timeout(5 * time.Second),
		nats.ReconnectWait(time.Second),
		nats.MaxReconnects(5),
	}

	if config.User != "" && config.Password != "" {
		opts = append(opts, nats.UserInfo(config.User, config.Password))
	}

	var whitelist []*net.IPNet
	for _, cidr := range config.SshFailures.Whitelist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR in whitelist: %s", cidr)
		}
		whitelist = append(whitelist, ipNet)
	}

	conn, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	return &Client{
		config:    config,
		conn:      conn,
		proxyId:   proxyId,
		whitelist: whitelist,
	}, nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) publish(subject string, data []byte) error {
	return c.conn.Publish(subject, data)
}

// publishFailedConnection publishes a failed connection event to NATS
func (c *Client) PublishFailedConnection(clientIP string, clientPort int, username string,
	failureInfo []string) error {
	if !c.config.SshFailures.Enabled {
		return nil
	}

	if c.config.SshFailures.PublicIPOnly && !isPublicIP(clientIP) {
		return nil
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return fmt.Errorf("failed to parse client IP: %s", clientIP)
	}

	if len(c.whitelist) > 0 {
		whitelisted := false
		for _, ipNet := range c.whitelist {
			if ipNet.Contains(ip) {
				whitelisted = true
				break
			}
		}
		if !whitelisted {
			return nil
		}
	}

	event := FailedConnectionEvent{
		ClientIP:    clientIP,
		ClientPort:  clientPort,
		Username:    username,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		FailureInfo: failureInfo,
		ProxyID:     c.proxyId,
	}

	eventBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal failed connection event: %w", err)
	}

	subject := c.config.SshFailures.Subject
	err = c.publish(subject, eventBytes)
	if err != nil {
		return fmt.Errorf("failed to publish failed connection event to NATS subject: %w", err)
	}
	return nil
}

// isPublicIP checks if the given IP address is a public IP
func isPublicIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return !parsedIP.IsPrivate() &&
		!parsedIP.IsLoopback() &&
		!parsedIP.IsLinkLocalUnicast() &&
		!parsedIP.IsLinkLocalMulticast() &&
		!parsedIP.IsMulticast() &&
		!parsedIP.IsUnspecified()
}
