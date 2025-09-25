package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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
	proxyFullID      string                    // identifier of the proxy with a PID where connection is established
	identity         *identity.Client          // identity client for interacting with the identity service
	k8shelld         *workspace.K8shelld       // k8shelld client for interacting with the workspace k8shelld daemon
	userStr          *models.UserStr           // user string information
	onboardCap       *models.OnboardCapability // onboarding capabilities
	onboardInfo      *models.OnboardUser       // onboarding information
	user             *models.User              // user information
	mu               sync.RWMutex              // mutex for synchronizing access
	session          *SessionInfo              // SSH session information
	directTCPIP      *sync.Map                 // direct TCP/IP connection information
	directTCPIPCount int64                     // current count of direct TCP/IP connections
	counters         *workspace.ConnCounters   // connection counters
	ctx              context.Context           // context for managing lifecycle
	cancel           context.CancelFunc        // function to cancel
	sessionID        int32                     // SSH session ID
	workspaceName    string                    // name of the workspace
	channelInfoMu    sync.RWMutex              // mutex for synchronizing access to channelInfo
	channelInfo      []string                  // channel information
	failureInfo      []string                  // failure information
	reportStopCh     chan struct{}             // channel to signal report goroutine to stop
	reportWg         sync.WaitGroup            // wait group for report goroutine
}

// SessionInfo holds information about a user's SSH session
type SessionInfo struct {
	username    string      // username of the user
	termWidth   uint32      // terminal width
	termHeight  uint32      // terminal height
	env         []string    // environment variables
	command     string      // command to execute
	hasPTY      bool        // true when the session has a pseudo-terminal
	sessionId   string      // unique session identifier
	hasAgent    bool        // true when the session has an SSH agent
	agentUnixID string      // unique identifier for the agent Unix socket
	sshAuthSock string      // value of SSH_AUTH_SOCK env variable
	signalChan  chan string `json:"-"`
}

type DirectTCPIPInfo struct {
	username      string // username of the user
	directTCPIPId string // unique identifier for the direct TCP/IP connection
	destHost      string // destination host
	destPort      uint32 // destination port
	originHost    string // origin host
	originPort    uint32 // origin port
}

// Global state storage
var connStates = make(map[string]*ConnectionInfo)
var connStatesMutex sync.RWMutex
var execSeqNumber int64 // sequence number for exec commands

func getConnectionID(remoteAddr string) string {
	connID := fmt.Sprintf("connid-%s", remoteAddr)
	return connID
}

func GetConnectionInfoByAddress(remoteAddr string) *ConnectionInfo {
	connID := getConnectionID(remoteAddr)
	connStatesMutex.RLock()
	defer connStatesMutex.RUnlock()

	connInfo := connStates[connID]
	return connInfo
}

func RemoveState(state *ConnectionInfo) {
	connStatesMutex.Lock()
	defer connStatesMutex.Unlock()
	delete(connStates, fmt.Sprintf("12345-%s", state.userStr.Username))
}

func (s *Server) GetConnInfo(conn ssh.ConnMetadata) (*ConnectionInfo, error) {
	userStr, err := models.NewUserStr(conn.User())
	if err != nil {
		return nil, fmt.Errorf("failed to parse user string: %w", err)
	}

	connID := getConnectionID(conn.RemoteAddr().String())

	connStatesMutex.RLock()
	connInfo := connStates[connID]
	connStatesMutex.RUnlock()

	if connInfo == nil {
		connStatesMutex.Lock()
		connInfo = connStates[connID]
		if connInfo == nil {
			ctx, cancel := context.WithCancel(context.Background())
			proxyID := GetProxyID()
			connInfo = &ConnectionInfo{
				identity:     s.identity,
				proxyFullID:  fmt.Sprintf("%s-%d", proxyID, os.Getpid()),
				userStr:      userStr,
				directTCPIP:  &sync.Map{},
				counters:     &workspace.ConnCounters{},
				ctx:          ctx,
				cancel:       cancel,
				sessionID:    0,
				reportStopCh: make(chan struct{}),
			}
			connInfo.reportWg.Add(1)
			connStates[connID] = connInfo
		}
		connStatesMutex.Unlock()
		if connInfo != nil {
			go connInfo.reportSessionData()
		}
	}

	return connInfo, nil
}

func (c *ConnectionInfo) AddFailureInfo(info string, err error) {
	if err != nil {
		c.failureInfo = append(c.failureInfo, fmt.Sprintf("%s: %v", info, err))
	} else {
		c.failureInfo = append(c.failureInfo, info)
	}
}

func (c *ConnectionInfo) AddChannelInfo(info string) {
	c.channelInfoMu.Lock()
	defer c.channelInfoMu.Unlock()
	c.channelInfo = append(c.channelInfo, info)
}

func (c *ConnectionInfo) GetChannelInfo() []string {
	c.channelInfoMu.RLock()
	defer c.channelInfoMu.RUnlock()

	seen := make(map[string]bool)
	unique := make([]string, 0, len(c.channelInfo))

	for _, item := range c.channelInfo {
		if !seen[item] {
			seen[item] = true
			unique = append(unique, item)
		}
	}

	sort.Strings(unique)
	return unique
}

func (c *ConnectionInfo) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.k8shelld != nil {
		_ = c.k8shelld.Close()
		c.k8shelld = nil
	}

	close(c.reportStopCh)
	c.reportWg.Wait()

	if err := c.sendUpdate(true); err != nil {
		return fmt.Errorf("failed to send final session update for user %s and session id %d: %w",
			c.userStr.Username, c.sessionID, err)
	}

	c.cancel()
	return nil
}

func (c *ConnectionInfo) sendUpdate(endSession bool) error {
	if c.sessionID == 0 || c.identity == nil {
		return nil
	}
	curIn, curOut := c.counters.Snapshot()
	curChannels := c.GetChannelInfo()

	if err := c.identity.UpdateSSHSession(
		c.ctx, c.userStr.Username, c.sessionID, curIn, curOut, "", curChannels,
	); err != nil {
		// log
	}

	if endSession {
		if err := c.identity.EndSSHSession(c.ctx, c.userStr.Username, c.sessionID); err != nil {
			return fmt.Errorf("failed to end SSH session %d for user %s: %w", c.sessionID, c.userStr.Username, err)
		}
	}
	return nil
}

func (c *ConnectionInfo) reportSessionData() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	defer c.reportWg.Done()

	for {
		select {
		case <-c.reportStopCh:
			return
		case <-t.C:
			c.sendUpdate(false)
		}
	}
}

func (c *ConnectionInfo) SetOnboardInfo(onboardInfo *models.OnboardUser) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onboardInfo = onboardInfo
}

func (c *ConnectionInfo) GetOnboardInfo() *models.OnboardUser {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.onboardInfo
}

func (c *ConnectionInfo) SetOnboardCap(onboardCap *models.OnboardCapability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onboardCap = onboardCap
}

func (c *ConnectionInfo) GetOnboardCap() *models.OnboardCapability {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.onboardCap
}

func (c *ConnectionInfo) Handshake(writer io.Writer,
	writerOptions *workspace.InfoWriterOptions, client *provisioner.Client,
	envVars []string) (*workspace.K8shelld, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.k8shelld != nil {
		return c.k8shelld, nil
	}

	infoWriter := workspace.NewInfoWriter(writer, writerOptions)

	if !c.user.IsValid {
		infoWriter.WriteError("User is not valid. Please contact the system administrator.")
		return nil, fmt.Errorf("user %q is not valid", c.user.Username)
	}

	if c.user.Locked {
		infoWriter.WriteError("User account is locked. Please contact the system administrator.")
		return nil, fmt.Errorf("user %s is locked", c.user.Username)
	}

	if !c.userStr.HasCustomBlueprint && !c.user.HasBlueprint(c.userStr.Blueprint) {
		infoWriter.WriteError(fmt.Sprintf("Access denied: user %s does not have access to blueprint %s.",
			c.user.Username, c.userStr.Blueprint))
		return nil, fmt.Errorf("user %s does not have access to blueprint %s",
			c.user.Username, c.userStr.Blueprint)
	}

	status, err := workspace.EnsureWorkspace(c.ctx, c.userStr, infoWriter, client)
	if err != nil {
		var provisionErr *workspace.ProvisionError
		if errors.As(err, &provisionErr) {
			infoWriter.WriteError(provisionErr.Message)
		} else {
			infoWriter.WriteSystemError(err.Error())
		}
		return nil, fmt.Errorf("failed to ensure workspace for user %s: %w", c.userStr.Username, err)
	}
	infoWriter.WriteMessage(fmt.Sprintf("Connecting to the workspace at %s...", status.Host))

	k8shelld, err := workspace.NewK8shelld(status.Host, status.PodIP, status.Port, status.AccessKey,
		status.TLSCert, c.counters)
	if err != nil {
		infoWriter.WriteSystemError(err.Error())
		return nil, fmt.Errorf("failed to create k8shelld client for user %s: %w", c.user.Username, err)
	}

	handshake, err := k8shelld.Handshake(c.ctx, c.user, envVars)
	if err != nil {
		infoWriter.WriteSystemError(err.Error())
		return nil, fmt.Errorf("handshake with k8shelld failed for user %s: %w", c.user.Username, err)
	}
	if !handshake.Accepted {
		infoWriter.WriteSystemError("Connection to the workspace was rejected.")
		return nil, fmt.Errorf("handshake with k8shelld failed for user %s", c.user.Username)
	}
	if writer != nil {
		infoWriter.WriteMessage(fmt.Sprintf("Connected to k8shelld (version: %s)\r\n", handshake.ServerVersion))
		if status.Splash != "" {
			infoWriter.WriteSplash(status.Splash)
		}
	}
	c.k8shelld = k8shelld
	c.workspaceName = status.Name

	// create session
	sshSession, err := c.identity.CreateSSHSession(c.ctx, c.user.Username, c.workspaceName,
		GetProxyID(), os.Getpid(), c.clientIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session for user %s: %w", c.user.Username, err)
	}
	atomic.StoreInt32(&c.sessionID, sshSession.SessionID)

	return c.k8shelld, nil
}

// IncrementDirectTCPIPCount atomically increments the direct TCP/IP count
func (c *ConnectionInfo) IncrementDirectTCPIPCount(maxLimit int) bool {
	for {
		current := atomic.LoadInt64(&c.directTCPIPCount)
		if current >= int64(maxLimit) {
			return false
		}

		if atomic.CompareAndSwapInt64(&c.directTCPIPCount, current, current+1) {
			return true
		}
	}
}

// DecrementDirectTCPIPCount atomically decrements the direct TCP/IP count
func (c *ConnectionInfo) DecrementDirectTCPIPCount() {
	for {
		current := atomic.LoadInt64(&c.directTCPIPCount)
		if current <= 0 {
			return
		}

		if atomic.CompareAndSwapInt64(&c.directTCPIPCount, current, current-1) {
			return
		}
	}
}

// GetDirectTCPIPCount returns the current direct TCP/IP count
func (c *ConnectionInfo) GetDirectTCPIPCount() int {
	return int(atomic.LoadInt64(&c.directTCPIPCount))
}

func (c *ConnectionInfo) ExecSeqNumber() int64 {
	return atomic.AddInt64(&execSeqNumber, 1)
}
