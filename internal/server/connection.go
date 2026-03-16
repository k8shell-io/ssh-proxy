// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/rand"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	natsc "github.com/k8shell-io/common/pkg/nats"
	identity "github.com/k8shell-io/identity/pkg/api"
	"github.com/k8shell-io/k8shelld/pkg/api"
	"github.com/k8shell-io/provisioner/pkg/api/provisionerpb"
	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

// Connection represents the connection information for a user
type Connection struct {
	ctx          context.Context    // context for managing the connection
	seqNumberGen int64              // sequence number for exec commands
	connId       string             // session key for the connection
	cancel       context.CancelFunc // function to cancel the context
	log          *zerolog.Logger    // logger instance, reused from server
	userStr      *models.UserStr    // user string information
	clientIP     string             // client IP address (detected from proxy protocol if available)
	clientPort   int                // client port (detected from proxy protocol if available)
	// proxyFullID      string                        // identifier of the proxy with a PID suffix
	identity         *identity.Client              // identity client for interacting with the identity service
	sessionKV        *natsc.JetStreamKV            // KV instance for storing session data
	k8shelldCfg      gapi.ClientConfig             // k8shelld client configuration
	k8shelld         workspace.K8shelldClient      // client for interacting with the workspace k8shelld daemon
	k8shelldVer      string                        // version of the k8shelld daemon
	onboardMu        sync.RWMutex                  // mutex for synchronizing access to onboardInfo and onboardCap
	onboardCap       *models.OnboardCapability     // onboarding capabilities
	onboardInfo      *models.OnboardUserDeviceFlow // onboarding information
	user             *models.User                  // user information
	mu               sync.RWMutex                  // mutex for synchronizing access
	session          *Session                      // SSH session information
	directTCPIP      *sync.Map                     // direct TCP/IP connection information
	directTCPIPCount int64                         // current count of direct TCP/IP connections
	counters         *api.ConnCounters             // connection counters
	workspaceName    string                        // name of the workspace
	channelInfoMu    sync.RWMutex                  // mutex for synchronizing access to channelInfo
	channelInfo      []string                      // channel information
	failureInfo      []string                      // failure information
	reportStopCh     chan struct{}                 // channel to signal report goroutine to stop
	reportWg         sync.WaitGroup                // wait group for report goroutine
}

// Session holds information about a user's SSH session
type Session struct {
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

// Global state storage
var connStates = make(map[string]*Connection)
var connStatesMutex sync.RWMutex

// SESSION_UPDATE_INTERVAL defines the interval for session updates
const SESSION_UPDATE_INTERVAL = 10 * time.Second

// getConnectionID generates a connection ID based on the remote address
func getConnectionID(remoteAddr string) string {
	connID := fmt.Sprintf("connid-%s", remoteAddr)
	return connID
}

// GetConnectionByAddress retrieves the Connection object based on the remote address
func GetConnectionByAddress(remoteAddr string) *Connection {
	connID := getConnectionID(remoteAddr)
	connStatesMutex.RLock()
	defer connStatesMutex.RUnlock()

	connInfo := connStates[connID]
	return connInfo
}

// RemoveState removes the connection state for a given Connection object
func RemoveState(state *Connection) {
	connStatesMutex.Lock()
	defer connStatesMutex.Unlock()
	delete(connStates, fmt.Sprintf("connid-%s", state.userStr.Username))
}

// GetConnInfo retrieves or creates a Connection object for the given ssh.ConnMetadata
func (s *Server) GetConnInfo(conn ssh.ConnMetadata) (*Connection, error) {
	userStr, err := models.NewUserStr(conn.User(), true)
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
			connInfo = &Connection{
				connId:       fmt.Sprintf("%s-%d-%s", GetProxyID(), os.Getpid(), strings.ToLower(rand.Text()[:2])),
				log:          s.log,
				identity:     s.identity,
				sessionKV:    s.sessionKV,
				k8shelldCfg:  s.Config.K8shelld,
				userStr:      userStr,
				directTCPIP:  &sync.Map{},
				counters:     &api.ConnCounters{},
				ctx:          ctx,
				cancel:       cancel,
				reportStopCh: make(chan struct{}),
				onboardMu:    sync.RWMutex{},
			}
			connStates[connID] = connInfo
		}
		connStatesMutex.Unlock()
	}

	return connInfo, nil
}

// AddFailureInfo appends failure information to the Connection object
func (c *Connection) AddFailureInfo(info string, err error) {
	if err != nil {
		c.failureInfo = append(c.failureInfo, fmt.Sprintf("%s: %v", info, err))
	} else {
		c.failureInfo = append(c.failureInfo, info)
	}
}

// AddChannelInfo appends channel information to the Connection object
func (c *Connection) AddChannelInfo(info string) {
	c.channelInfoMu.Lock()
	defer c.channelInfoMu.Unlock()
	c.channelInfo = append(c.channelInfo, info)
}

// GetChannelInfo retrieves a sorted list of unique channel information
func (c *Connection) GetChannelInfo() []string {
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

// Close cleans up the Connection object and sends the final session update
func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.k8shelld != nil {
		_ = c.k8shelld.Close()
		c.k8shelld = nil
	}

	if c.sessionKV != nil {
		close(c.reportStopCh)
		c.reportWg.Wait()
	}

	//c.cancel()
	return nil
}

// reportSessionData periodically reports session data
func (c *Connection) reportSessionData() {
	t := time.NewTicker(SESSION_UPDATE_INTERVAL)
	defer t.Stop()
	defer c.reportWg.Done()
	_, err := c.updateSession("create")
	if err != nil {
		c.log.Debug().Msgf("Failed to create session data for user %s: %v", c.user.Username, err)
	}

	for {
		select {
		case <-c.reportStopCh:
			_, err := c.updateSession("delete")
			if err != nil {
				c.log.Debug().Msgf("Failed to delete session data for user %s: %v", c.user.Username, err)
			}
			return
		case <-t.C:
			closed, err := c.updateSession("update")
			if err != nil {
				c.log.Debug().Msgf("Failed to update session data for user %s: %v", c.user.Username, err)
			}
			if closed {
				return
			}
		}
	}
}

// updateSession sends the current session update to the identity provider
func (c *Connection) updateSession(action string) (bool, error) {
	curIn, curOut := c.counters.Snapshot()
	curChannels := c.GetChannelInfo()

	t := time.Now().UTC()

	e, err := c.sessionKV.Get(c.connId)
	if errors.Is(err, nats.ErrKeyNotFound) && action == "create" {
		d := models.SSHSession{
			SessionID:   c.connId,
			K8shelldVer: c.k8shelldVer,
			ClientIP:    c.clientIP,
			Client:      "",
			Username:    c.user.Username,
			Workspace:   c.workspaceName,
			BytesIn:     curIn,
			BytesOut:    curOut,
			Channels:    curChannels,
			StartTime:   &t,
			UpdatedAt:   &t,
			Blueprint:   c.userStr.Blueprint,
		}
		var payload []byte
		payload, err = json.Marshal(d)
		if err != nil {
			return false, fmt.Errorf("failed to marshal session data: %w", err)
		}
		_, err = c.sessionKV.Create(c.connId, payload)
	} else if err == nil {
		var d models.SSHSession
		err = json.Unmarshal(e.Value(), &d)
		if err != nil {
			return false, fmt.Errorf("failed to unmarshal session data: %w", err)
		}

		d.BytesIn = curIn
		d.BytesOut = curOut
		d.Channels = curChannels
		d.UpdatedAt = &t

		var payload []byte
		payload, err = json.Marshal(d)
		if err != nil {
			return false, fmt.Errorf("failed to marshal session data: %w", err)
		}
		_, err = c.sessionKV.Update(c.connId, payload, e.Revision())
	}

	if errors.Is(err, nats.ErrKeyNotFound) {
		// Key not found on update; close the connection
		c.cancel()
		return true, nil
	} else if err != nil {
		c.log.Debug().Msgf("Failed to update session data in cache: key=%s, err=%v", c.connId, err)
	}

	if action == "delete" {
		err := c.sessionKV.Delete(c.connId)
		if err != nil {
			c.log.Debug().Msgf("Failed to delete session data for user %s: %v", c.user.Username, err)
		}
	}

	return false, nil
}

// SetOnboardInfo sets the onboarding information for the Connection object
func (c *Connection) SetOnboardInfo(onboardInfo *models.OnboardUserDeviceFlow) {
	c.onboardMu.Lock()
	defer c.onboardMu.Unlock()
	c.onboardInfo = onboardInfo
}

// GetOnboardInfo retrieves the onboarding information for the Connection object
func (c *Connection) GetOnboardInfo() *models.OnboardUserDeviceFlow {
	c.onboardMu.RLock()
	defer c.onboardMu.RUnlock()
	return c.onboardInfo
}

// SetOnboardCap sets the onboarding capabilities for the Connection object
func (c *Connection) SetOnboardCap(onboardCap *models.OnboardCapability) {
	c.onboardMu.Lock()
	defer c.onboardMu.Unlock()
	c.onboardCap = onboardCap
}

// GetOnboardCap retrieves the onboarding capabilities for the Connection object
func (c *Connection) GetOnboardCap() *models.OnboardCapability {
	c.onboardMu.RLock()
	defer c.onboardMu.RUnlock()
	return c.onboardCap
}

// Handshake performs the handshake with the k8shelld daemon and ensures the workspace is ready
// It checks the user validity and access to the specified workspace blueprint and starts
// the workspace if it is not running. It also creates an SSH session record in the identity service.
func (c *Connection) Handshake(writer io.Writer, writerOptions *workspace.InfoWriterOptions,
	backends workspace.Backends, envVars []string) (workspace.K8shelldClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.k8shelld != nil {
		return c.k8shelld, nil
	}

	infoWriter := workspace.NewInfoWriter(writer, writerOptions)

	if c.userStr.ValidationError != nil {
		infoWriter.WriteError("Invalid user string: " + c.userStr.ValidationError.Error())
		return nil, fmt.Errorf("invalid user string for user %s: %w",
			c.userStr.Username, c.userStr.ValidationError)
	}

	if !c.user.IsValid {
		infoWriter.WriteError("User is not valid. Please contact the system administrator.")
		return nil, fmt.Errorf("user %q is not valid", c.user.Username)
	}

	if c.user.Locked {
		infoWriter.WriteError("User account is locked. Please contact the system administrator.")
		return nil, fmt.Errorf("user %s is locked", c.user.Username)
	}

	if c.userStr.BlueprintKind != models.BlueprintKindCustom && !c.user.HasBlueprint(c.userStr.Blueprint) {
		infoWriter.WriteError(fmt.Sprintf("Access denied: user %s does not have access to blueprint %s.",
			c.user.Username, c.userStr.Blueprint))
		return nil, fmt.Errorf("user %s does not have access to blueprint %s",
			c.user.Username, c.userStr.Blueprint)
	}

	status, err := workspace.EnsureWorkspace(c.ctx, c.userStr, infoWriter, backends)
	if err != nil {
		var provisionErr *workspace.ProvisionError
		if errors.As(err, &provisionErr) {
			infoWriter.WriteError(provisionErr.Message)
		} else {
			infoWriter.WriteSystemError(err.Error())
		}
		return nil, fmt.Errorf("failed to ensure workspace for user %s: %w", c.userStr.Username, err)
	}
	infoWriter.WriteMessage(fmt.Sprintf("Connecting to the workspace at %s...", status.ServerName))

	k8shelld, err := workspace.NewK8shelld(c.k8shelldCfg, status, c.counters)
	if err != nil {
		infoWriter.WriteSystemError(err.Error())
		return nil, fmt.Errorf("failed to create k8shelld client for user %s: %w", c.user.Username, err)
	}

	c.log.Debug().Msgf("Connecting to k8shelld at %s:%d for user %s, version: %s",
		status.ServerName, status.Port, c.user.Username, status.AppVersion)

	handshake, err := k8shelld.Handshake(c.ctx, c.user, envVars)
	if err != nil {
		infoWriter.WriteSystemError(err.Error())
		return nil, fmt.Errorf("handshake with k8shelld failed for user %s: %w", c.user.Username, err)
	}
	if !handshake.Accepted {
		infoWriter.WriteSystemError("Connection to the workspace was rejected.")
		return nil, fmt.Errorf("handshake with k8shelld failed for user %s", c.user.Username)
	}

	go func() {
		c.log.Debug().Msgf("Running k8shelld command processor for user %s", c.user.Username)
		err = k8shelld.RunCommandProcessor(c.ctx, c.getCommandHandler(backends, status.Name))
		if err != nil {
			c.log.Error().Msgf("Failed to run k8shelld command processor for user %s: %v", c.user.Username, err)
		} else {
			c.log.Debug().Msgf("k8shelld command processor stopped for user %s", c.user.Username)
		}
	}()

	c.k8shelld = k8shelld
	c.k8shelldVer = status.AppVersion
	c.workspaceName = status.Name

	if c.sessionKV != nil {
		c.reportWg.Add(1)
		go c.reportSessionData()
	}

	return c.k8shelld, nil
}

func (c *Connection) getCommandHandler(backends workspace.Backends, workspaceName string) api.CommandHandler {
	return func(ctx context.Context, command string) (string, error) {
		switch command {
		case "shutdown":
			c.log.Debug().Msgf("Received k8shelld shutdown command for user %s, workspace %s",
				c.user.Username, workspaceName)
			_, err := backends.Provisioner().DeleteWorkspace(c.ctx,
				&provisionerpb.DeleteWorkspaceRequest{Workspace: workspaceName, DelaySeconds: 2})
			if err != nil {
				c.log.Debug().Msgf("Failed to delete workspace for user %s, workspace %s: %v",
					c.user.Username, workspaceName, err)
				return "Cannot shutdown workspace due to an error.",
					fmt.Errorf("failed to delete (shutdown) workspace: %w", err)
			}
			return "Workspace shutdown has been initiated.", nil
		}
		c.log.Error().Msgf("Received unknown k8shelld command %q for user %s, workspace %s",
			command, c.user.Username, workspaceName)
		return "", fmt.Errorf("unknown command")
	}
}

// IncrementDirectTCPIPCount atomically increments the direct TCP/IP count
func (c *Connection) IncrementDirectTCPIPCount(maxLimit int) bool {
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
func (c *Connection) DecrementDirectTCPIPCount() {
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
func (c *Connection) GetDirectTCPIPCount() int {
	return int(atomic.LoadInt64(&c.directTCPIPCount))
}

// SeqNumber returns a unique sequence number for exec commands
func (c *Connection) SeqNumber() int64 {
	return atomic.AddInt64(&c.seqNumberGen, 1)
}
