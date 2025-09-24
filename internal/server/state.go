package server

import (
	"context"
	"errors"
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
	channelInfo      []string                  // channel information
	failureInfo      []string                  // failure information
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
		defer connStatesMutex.Unlock()

		connInfo = connStates[connID]
		if connInfo == nil {
			ctx, cancel := context.WithCancel(context.Background())
			proxyID := GetProxyID()
			connInfo = &ConnectionInfo{
				identity:    s.identity,
				proxyFullID: fmt.Sprintf("%s-%d", proxyID, os.Getpid()),
				userStr:     userStr,
				directTCPIP: &sync.Map{},
				counters:    &workspace.ConnCounters{},
				ctx:         ctx,
				cancel:      cancel,
				sessionID:   0,
			}
			connStates[connID] = connInfo
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
}

func (c *ConnectionInfo) reportSessionData() {
	t := time.NewTicker(10 * time.Second)

	prevIn, prevOut := c.counters.Snapshot()
	var prevChannelInfo []string

	getSessionID := func() int32 {
		return atomic.LoadInt32(&c.sessionID)
	}

	sendUpdate := func(reqCtx context.Context, sessionID int32) {
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
			reqCtx, c.userStr.Username, sessionID, sendIn, sendOut, "", sendChannels,
		)
	}

	defer func() {
		fmt.Printf("DEBUG: reportSessionData cleanup starting for user %s\n", c.userStr.Username)
		if sid := getSessionID(); sid != 0 {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			sendUpdate(cleanupCtx, sid)
			_ = c.identity.EndSSHSession(cleanupCtx, c.userStr.Username, sid)
			fmt.Printf("**** Session %d for user %s ended and reported final data\n", sid, c.userStr.Username)
		}
		t.Stop()
		fmt.Printf("DEBUG: reportSessionData cleanup completed for user %s\n", c.userStr.Username)
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			if sid := getSessionID(); sid != 0 {
				sendUpdate(c.ctx, sid)
			}
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

func (c *ConnectionInfo) CreateK8shelldClient(ctx context.Context, writer io.Writer,
	writerOptions *workspace.InfoWriterOptions, client *provisioner.Client,
	envVars []string) (*workspace.K8shelld, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.k8shelld != nil {
		return c.k8shelld, nil
	}

	infoWriter := workspace.NewInfoWriter(writer, writerOptions)

	status, err := workspace.EnsureWorkspace(ctx, c.userStr, infoWriter, client)
	if err != nil {
		var provisionErr *workspace.ProvisionError
		if errors.As(err, &provisionErr) {
			infoWriter.WriteError(provisionErr.Message)
		}
		return nil, fmt.Errorf("failed to ensure workspace for user %s: %w", c.userStr.Username, err)
	}
	infoWriter.WriteMessage(fmt.Sprintf("Connecting to the workspace at %s...", status.Host))

	k8shelld, err := workspace.NewK8shelld(status.Host, status.PodIP, status.Port, status.AccessKey, status.TLSCert)
	if err != nil {
		infoWriter.WriteSystemError(err.Error())
		return nil, fmt.Errorf("failed to create k8shelld client for user %s: %w", c.user.Username, err)
	}

	handshake, err := k8shelld.Handshake(ctx, c.user, envVars)
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
	sshSession, err := c.identity.CreateSSHSession(ctx, c.user.Username, c.workspaceName,
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
