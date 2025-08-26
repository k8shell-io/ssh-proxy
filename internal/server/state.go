package server

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/k8shell-io/common/models"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"golang.org/x/crypto/ssh"
)

// ConnectionInfo represents the connection information for a user
type ConnectionInfo struct {
	proxyID          string                    // unique identifier of the proxy where connection is established
	k8shelld         *workspace.K8shelld       // k8shelld client for interacting with the workspace k8shelld daemon
	UserStr          *models.UserStr           // user string information
	OnboardCap       *models.OnboardCapability // onboarding capabilities
	OnboardInfo      *models.OnboardUser       // onboarding information
	User             *models.User              // user information
	AuthFailCount    int                       // number of failed authentication attempts
	AuthLastAttempt  time.Time                 // timestamp of the last authentication attempt
	mu               sync.RWMutex              // mutex for synchronizing access
	Session          *SessionInfo              // SSH session information
	DirectTCPIP      *sync.Map                 // direct TCP/IP connection information
	DirectTCPIPCount int64                     // current count of direct TCP/IP connections
}

// SessionInfo holds information about a user's SSH session
type SessionInfo struct {
	Username     string        // username of the user
	TermType     string        // terminal type
	TermWidth    uint32        // terminal width
	TermHeight   uint32        // terminal height
	TermWidthPx  uint32        // terminal width in pixels
	TermHeightPx uint32        // terminal height in pixels
	Env          []string      // environment variables
	Command      string        // command to execute
	HasPTY       bool          // true when the session has a pseudo-terminal
	SessionId    string        // unique session identifier
	ShellReady   chan struct{} // channel to signal when the shell is ready
	HasAgent     bool          // true when the session has an SSH agent
	AgentChannel ssh.Channel   // channel for the SSH agent
	AgentUnixID  string        // unique identifier for the agent Unix socket
	SSHAuthSock  string        // value of SSH_AUTH_SOCK env variable
	SignalChan   chan string   `json:"-"`
}

type DirectTCPIPInfo struct {
	Username      string // username of the user
	DirectTCPIPId string // unique identifier for the direct TCP/IP connection
	DestHost      string // destination host
	DestPort      uint32 // destination port
	OriginHost    string // origin host
	OriginPort    uint32 // origin port
}

// Global state storage
var connStates = make(map[string]*ConnectionInfo)
var connStatesMutex sync.RWMutex
var execSeqNumber int64 // sequence number for exec commands

func getConnectionID(conn ssh.ConnMetadata, userStr *models.UserStr) string {
	connID := fmt.Sprintf("%s-%s", conn.RemoteAddr(), userStr.Username)
	return connID
}

func RemoveState(state *ConnectionInfo) {
	connStatesMutex.Lock()
	defer connStatesMutex.Unlock()
	delete(connStates, fmt.Sprintf("12345-%s", state.UserStr.Username))
}

func GetConnInfo(conn ssh.ConnMetadata) (*ConnectionInfo, error) {
	userStr, err := models.NewUserStr(conn.User())
	if err != nil {
		return nil, fmt.Errorf("failed to parse user string: %w", err)
	}

	connID := getConnectionID(conn, userStr)

	connStatesMutex.RLock()
	defer connStatesMutex.RUnlock()
	connInfo := connStates[connID]
	if connInfo == nil {
		connInfo = &ConnectionInfo{
			proxyID:     GetProxyID(),
			UserStr:     userStr,
			DirectTCPIP: &sync.Map{},
		}
		connStates[connID] = connInfo
	}
	return connInfo, nil
}

func (s *ConnectionInfo) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.k8shelld != nil {
		s.k8shelld.Close()
		s.k8shelld = nil
	}
}

func (s *ConnectionInfo) SetOnboardInfo(onboardInfo *models.OnboardUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OnboardInfo = onboardInfo
}

func (s *ConnectionInfo) GetOnboardInfo() *models.OnboardUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OnboardInfo
}

func (s *ConnectionInfo) SetOnboardCap(onboardCap *models.OnboardCapability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OnboardCap = onboardCap
}

func (s *ConnectionInfo) GetOnboardCap() *models.OnboardCapability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OnboardCap
}

func (c *ConnectionInfo) CreateK8shelldClient(ctx context.Context, writer io.Writer,
	client *provisioner.Client) (*workspace.K8shelld, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.k8shelld != nil {
		return c.k8shelld, nil
	}

	status, err := workspace.EnsureWorkspace(ctx, c.UserStr, writer, client)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure workspace for user %s: %w", c.UserStr.Username, err)
	}
	if writer != nil {
		writer.Write([]byte(fmt.Sprintf("Connecting to the workspace at %s...\r\n", status.Host)))
	}

	k8shelld, err := workspace.NewK8shelld(status.Host, status.PodIP, status.Port, status.AccessKey, status.TLSCert)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8shelld client for user %s: %w", c.User.Username, err)
	}

	handshake, err := k8shelld.Handshake(ctx, c.User)
	if err != nil {
		return nil, fmt.Errorf("handshake with k8shelld failed for user %s: %w", c.User.Username, err)
	}
	if !handshake.Accepted {
		return nil, fmt.Errorf("handshake with k8shelld failed for user %s", c.User.Username)
	}
	if writer != nil {
		writer.Write([]byte(fmt.Sprintf("Connected to k8shelld (version: %s)\r\n",
			handshake.ServerVersion)))
	}
	c.k8shelld = k8shelld

	return c.k8shelld, nil
}

// IncrementDirectTCPIPCount atomically increments the direct TCP/IP count
func (c *ConnectionInfo) IncrementDirectTCPIPCount(maxLimit int) bool {
	for {
		current := atomic.LoadInt64(&c.DirectTCPIPCount)
		if current >= int64(maxLimit) {
			return false
		}

		if atomic.CompareAndSwapInt64(&c.DirectTCPIPCount, current, current+1) {
			return true
		}
	}
}

// DecrementDirectTCPIPCount atomically decrements the direct TCP/IP count
func (c *ConnectionInfo) DecrementDirectTCPIPCount() {
	for {
		current := atomic.LoadInt64(&c.DirectTCPIPCount)
		if current <= 0 {
			return
		}

		if atomic.CompareAndSwapInt64(&c.DirectTCPIPCount, current, current-1) {
			return
		}
	}
}

// GetDirectTCPIPCount returns the current direct TCP/IP count
func (c *ConnectionInfo) GetDirectTCPIPCount() int {
	return int(atomic.LoadInt64(&c.DirectTCPIPCount))
}

func (c *ConnectionInfo) ExecSeqNumber() int64 {
	return atomic.AddInt64(&execSeqNumber, 1)
}
