package server

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/k8shell-io/common/pkg/logger"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

type NatsFailuresPublisher struct {
	log            *zerolog.Logger
	natsConfig     natsc.NATSClientConfig
	failuresConfig PublishSshFailuresConfig
	conn           *nats.Conn
	proxyId        string
}

// FailureEvent represents a failed SSH connection attempt
type FailureEvent struct {
	ClientIP    string   `json:"client_ip"`
	ClientPort  int      `json:"client_port"`
	Username    string   `json:"username"`
	Timestamp   string   `json:"timestamp"`
	FailureInfo []string `json:"failure_info"`
	ProxyID     string   `json:"proxy_id"`
}

// NewNatsFailuresPublisher creates a new NATS failures publisher with the given configuration
func NewNatsFailuresPublisher(natsConfig natsc.NATSClientConfig, failuresConfig PublishSshFailuresConfig) (*NatsFailuresPublisher, error) {
	opts := natsc.NatsOptionsFromConfig("ssh-proxy", natsConfig)

	conn, err := nats.Connect(natsConfig.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	if failuresConfig.Enabled {
		logger.NewLogger("ssh-failures").Info().Msg("NATS SSH failures publishing is enabled")
	} else {
		logger.NewLogger("ssh-failures").Info().Msg("NATS SSH failures publishing is disabled")
	}

	return &NatsFailuresPublisher{
		log:            logger.NewLogger("ssh-failures"),
		natsConfig:     natsConfig,
		failuresConfig: failuresConfig,
		conn:           conn,
		proxyId:        GetProxyID(),
	}, nil
}

// Close closes the NATS client connection
func (c *NatsFailuresPublisher) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// publishFailedConnection publishes a failed connection event to NATS
func (c *NatsFailuresPublisher) PublishFailure(clientIP string, clientPort int, username string,
	failureInfo []string) error {
	if !c.failuresConfig.Enabled {
		return nil
	}

	if c.failuresConfig.PublicIPOnly && !isPublicIP(clientIP) {
		c.log.Debug().Msgf("Ignoring failed connection event (public IP only): ip=%s, failure-info=%+v",
			clientIP, failureInfo)
		return nil
	}

	event := FailureEvent{
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

	subject := c.failuresConfig.Subject
	c.log.Debug().Msgf("Publishing failed connection event: subject=%s, event=%+v", subject, event)
	err = c.conn.Publish(subject, eventBytes)
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
