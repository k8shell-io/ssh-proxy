package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/k8shell-io/common/models"
	identity "github.com/k8shell-io/identity/pkg/client"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"golang.org/x/crypto/ssh"
)

// ConnectionInfo represents the connection information for a user
type ConnectionInfo struct {
	clientIP         string
	clientPort       int
	proxyFullID      string                    // unique identifier of the proxy with a PID where connection is established
	identity         *identity.Client          // identity client for interacting with the identity service
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
	counters         *workspace.ConnCounters   // connection counters
	cancel           context.CancelFunc        // function to cancel
	sessionID        int32                     // SSH session ID
	workspaceName    string                    // name of the workspace
	channelInfo      []string                  // channel information
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

func (s *Server) GetConnInfo(conn ssh.ConnMetadata) (*ConnectionInfo, error) {
	userStr, err := models.NewUserStr(conn.User())
	if err != nil {
		return nil, fmt.Errorf("failed to parse user string: %w", err)
	}

	connID := getConnectionID(conn, userStr)

	connStatesMutex.RLock()
	defer connStatesMutex.RUnlock()

	connInfo := connStates[connID]
	if connInfo == nil {
		ctx, cancel := context.WithCancel(context.Background())
		proxyID := GetProxyID()
		connInfo = &ConnectionInfo{
			identity:    s.identity,
			proxyFullID: fmt.Sprintf("%s-%d", proxyID, os.Getpid()),
			UserStr:     userStr,
			DirectTCPIP: &sync.Map{},
			counters:    &workspace.ConnCounters{},
			cancel:      cancel,
			sessionID:   0,
		}
		connStates[connID] = connInfo
		go connInfo.reportSessionData(ctx)
	}
	return connInfo, nil
}

func (c *ConnectionInfo) AddChannelInfo(info string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.channelInfo = append(c.channelInfo, info)
}

func (c *ConnectionInfo) GetChannelInfo() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.channelInfo
}

func (c *ConnectionInfo) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.k8shelld != nil {
		c.k8shelld.Close()
		c.k8shelld = nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	if c.sessionID != 0 {
		c.identity.EndSSHSession(context.Background(), c.UserStr.Username, c.sessionID)
	}
}

func (c *ConnectionInfo) reportSessionData(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	prevIn, prevOut := c.counters.Snapshot()
	var prevChannelInfo []string

	getSessionID := func() int32 {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.sessionID
	}

	sendUpdate := func(sessionID int32) {
		curIn, curOut := c.counters.Snapshot()
		curChannels := c.GetChannelInfo()

		sendIn := int64(0)
		sendOut := int64(0)
		if curIn != prevIn {
			sendIn = curIn
		}
		if curOut != prevOut {
			sendOut = curOut
		}

		var sendChannels []string
		if !slices.Equal(curChannels, prevChannelInfo) {
			sendChannels = append([]string(nil), curChannels...)
		} else {
			sendChannels = []string{}
		}

		prevIn, prevOut = curIn, curOut
		prevChannelInfo = append([]string(nil), curChannels...)

		_ = c.identity.UpdateSSHSession(
			ctx, c.UserStr.Username, sessionID, sendIn, sendOut, "", sendChannels,
		)
	}

	for {
		select {
		case <-ctx.Done():
			if sid := getSessionID(); sid != 0 {
				sendUpdate(sid)
			}
			return
		case <-t.C:
			if sid := getSessionID(); sid != 0 {
				sendUpdate(sid)
			}
		}
	}
}

func (c *ConnectionInfo) SetOnboardInfo(onboardInfo *models.OnboardUser) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.OnboardInfo = onboardInfo
}

func (c *ConnectionInfo) GetOnboardInfo() *models.OnboardUser {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.OnboardInfo
}

func (c *ConnectionInfo) SetOnboardCap(onboardCap *models.OnboardCapability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.OnboardCap = onboardCap
}

func (c *ConnectionInfo) GetOnboardCap() *models.OnboardCapability {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.OnboardCap
}

func (c *ConnectionInfo) CreateK8shelldClient(ctx context.Context, writer io.Writer, showProvisionInfo bool,
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
	c.workspaceName = status.Name

	// create session
	sshSession, err := c.identity.CreateSSHSession(ctx, c.User.Username, c.workspaceName,
		GetProxyID(), os.Getpid(), c.clientIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session for user %s: %w", c.User.Username, err)
	}
	c.sessionID = sshSession.SessionID

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
