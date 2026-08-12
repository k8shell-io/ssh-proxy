// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
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

	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/k8shell-io/common/pkg/api/client/identity"
	"github.com/k8shell-io/common/pkg/api/client/k8shelld"
	sessionc "github.com/k8shell-io/common/pkg/api/client/session"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	sessionv1 "github.com/k8shell-io/common/pkg/api/gen/go/session/v1"
	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/userstr"
	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

// Connection represents the connection information for a user
type Connection struct {
	ctx              context.Context               // context for managing the connection
	seqNumberGen     int64                         // sequence number for exec commands
	connId           string                        // session key for the connection
	connKey          string                        // key under which this Connection is stored in connStates
	cancel           context.CancelFunc            // function to cancel the context
	log              *zerolog.Logger               // logger instance, reused from server
	transport        io.Closer                     // underlying SSH transport; set once the handshake completes, used to force-terminate the session
	userStr          *userstr.UserStr              // user string information
	clientIP         string                        // client IP address (detected from proxy protocol if available)
	clientPort       int                           // client port (detected from proxy protocol if available)
	identity         *identity.IdentityClient      // identity client for interacting with the identity service
	sessionClient    *sessionc.Client              // gRPC client for session tracking
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
	counters         *k8shelld.ConnCounters        // connection counters
	workspaceName    string                        // name of the workspace
	channelInfoMu    sync.RWMutex                  // mutex for synchronizing access to channelInfo
	channelInfo      []string                      // channel information
	failureInfo      []string                      // failure information
	reportStopCh     chan struct{}                 // channel to signal report goroutine to stop
	reportWg         sync.WaitGroup                // wait group for report goroutine
	ptyName          string                        // name of the allocated pseudo-terminal (if any)
	authMethodsMu    sync.RWMutex                  // mutex for synchronizing access to authMethods
	authMethods      []authz.UserAuthMethod        // SSH authentication methods permitted by policy (resolved once per connection)
	authMethodsSet   bool                          // whether authMethods has been resolved
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

// TokenCacheEntry represents a cached user token with metadata
type TokenCacheEntry struct {
	Token     string
	ExpiresAt time.Time
}

// Time before actual expiration to consider the token expired
const TokenExpirySkew = 2 * time.Minute

// userTokenCache stores user tokens with thread-safe access
var userTokenCache = make(map[string]*TokenCacheEntry)
var userTokenCacheMutex sync.RWMutex

// getCachedUserToken retrieves a user token from the cache if it exists and is not expired
func getCachedUserToken(user *models.User) (string, bool) {
	userTokenCacheMutex.RLock()
	defer userTokenCacheMutex.RUnlock()

	entry, exists := userTokenCache[user.Username+user.Source]
	if !exists {
		return "", false
	}

	if time.Until(entry.ExpiresAt) < TokenExpirySkew {
		return "", false
	}

	return entry.Token, true
}

// setCachedUserToken stores a user token in the cache with expiration time
func setCachedUserToken(user *models.User, token string) error {
	claims, err := authz.ParseUnverifiedClaims(token, true)
	if err != nil {
		return fmt.Errorf("failed to parse token claims: %w", err)
	}

	userTokenCacheMutex.Lock()
	defer userTokenCacheMutex.Unlock()

	userTokenCache[user.Username+user.Source] = &TokenCacheEntry{
		Token:     token,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	return nil
}

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
	delete(connStates, state.connKey)
}

// closeAllSSHConnectionsForUser force-closes every live SSH connection owned
// by username in this process. A user can hold more than one concurrent
// session (multiple terminals, port-forwards, etc.), so every match is
// closed, not just the first.
func closeAllSSHConnectionsForUser(username string) {
	connStatesMutex.RLock()
	matches := make([]*Connection, 0, 1)
	for _, c := range connStates {
		if connectionBelongsToUser(c, username) {
			matches = append(matches, c)
		}
	}
	connStatesMutex.RUnlock()

	for _, c := range matches {
		c.log.Info().Msgf("Closing SSH connection for locked user %s", username)
		c.ForceClose()
	}
}

// connectionBelongsToUser reports whether c belongs to username, preferring
// the identity-resolved username and falling back to the raw SSH login name
// for connections that haven't completed authentication yet.
func connectionBelongsToUser(c *Connection, username string) bool {
	if c.user != nil {
		return c.user.Username == username
	}
	return c.userStr != nil && c.userStr.Username() == username
}

// GetConnInfo retrieves or creates a Connection object for the given ssh.ConnMetadata
func (s *Server) GetConnInfo(conn ssh.ConnMetadata) (*Connection, error) {
	userStr, err := userstr.ParseUserStr(conn.User())
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
				connId:        fmt.Sprintf("%s-%d-%s", GetProxyID(), os.Getpid(), strings.ToLower(rand.Text()[:2])),
				connKey:       connID,
				log:           s.log,
				identity:      s.identity,
				sessionClient: s.sessionClient,
				k8shelldCfg:   s.Config.K8shelld,
				userStr:       userStr,
				directTCPIP:   &sync.Map{},
				counters:      &k8shelld.ConnCounters{},
				ctx:           ctx,
				cancel:        cancel,
				reportStopCh:  make(chan struct{}),
				onboardMu:     sync.RWMutex{},
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

	if c.sessionClient != nil {
		close(c.reportStopCh)
		c.reportWg.Wait()
	}

	RemoveState(c)

	//c.cancel()
	return nil
}

// SetTransport records the underlying SSH transport for the connection, so
// it can be force-closed later (e.g. ForceClose) independently of the
// per-connection context.
func (c *Connection) SetTransport(transport io.Closer) {
	c.transport = transport
}

// ForceClose terminates the connection's underlying SSH transport, e.g. when
// the user's account becomes locked mid session. Closing the transport drops
// every open SSH channel (unblocking any in-flight reads/writes with EOF)
// and causes the channel loop to observe a closed channels chan, unwinding
// through the normal Close/RemoveState path. It deliberately does not cancel
// c.ctx: Close() reuses c.ctx to send the final session-delete update, and a
// canceled context would make that call fail immediately.
func (c *Connection) ForceClose() {
	if c.transport != nil {
		_ = c.transport.Close()
	}
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

// SetPtyName sets the name of the allocated pseudo-terminal for the Connection object
func (c *Connection) SetPtyName(ptyName string) {
	c.ptyName = ptyName
}

// updateSession sends the current session update to the session gRPC service
func (c *Connection) updateSession(action string) (bool, error) {
	curIn, curOut := c.counters.Snapshot()
	t := time.Now().UTC()

	if action == "delete" {
		_, err := c.sessionClient.EndSession(c.ctx, &sessionv1.EndSessionRequest{
			SessionId: c.connId,
			EndTime:   t.Unix(),
			BytesIn:   curIn,
			BytesOut:  curOut,
		})
		if err != nil {
			return false, fmt.Errorf("failed to end session: %w", err)
		}
		return false, nil
	}

	curChannels := c.GetChannelInfo()
	d := &models.SSHSession{
		SessionID:   c.connId,
		K8shelldVer: c.k8shelldVer,
		ClientIP:    c.clientIP,
		Client:      "",
		Username:    c.user.Username,
		Workspace:   c.workspaceName,
		BytesIn:     curIn,
		BytesOut:    curOut,
		Operations:  curChannels,
		UpdatedAt:   &t,
		Blueprint:   c.userStr.Blueprint(),
	}
	if action == "create" {
		d.StartTime = &t
	}

	_, err := c.sessionClient.UpsertSession(c.ctx, &sessionv1.UpsertSessionRequest{
		Session: sessionc.ToProtobufSession(d),
	})
	if err != nil {
		return false, fmt.Errorf("failed to upsert session: %w", err)
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

// SetAuthMethods caches the SSH authentication methods permitted by policy
// for this connection, so the user:auth policy is evaluated at most once per
// connection even though it gates both advertising (getAvailableAuthMethods)
// and enforcement (AuthPublicKey/AuthPassword).
func (c *Connection) SetAuthMethods(methods []authz.UserAuthMethod) {
	c.authMethodsMu.Lock()
	defer c.authMethodsMu.Unlock()
	c.authMethods = methods
	c.authMethodsSet = true
}

// GetAuthMethods retrieves the cached policy-permitted authentication methods.
// The second return value is false when the methods have not been resolved yet.
func (c *Connection) GetAuthMethods() ([]authz.UserAuthMethod, bool) {
	c.authMethodsMu.RLock()
	defer c.authMethodsMu.RUnlock()
	return c.authMethods, c.authMethodsSet
}

// grpcClientMessage returns a clean single-line message from an error,
// collapsing newlines and extra whitespace.
func grpcClientMessage(err error) string {
	msg := err.Error()
	msg = strings.NewReplacer("\r", " ", "\n", " ").Replace(msg)
	return strings.Join(strings.Fields(msg), " ")
}

// GetUserToken retrieves the user access token from the cache or the identity service.
func (c *Connection) GetUserToken() (string, error) {
	if cachedToken, found := getCachedUserToken(c.user); found {
		return cachedToken, nil
	}

	token, err := c.identity.IssueUserToken(c.ctx,
		&identityv1.IssueUserTokenRequest{
			Username: c.user.Username,
			Source:   c.user.Source},
	)
	if err != nil {
		return "", fmt.Errorf("failed to issue access token for user %s: %w", c.user.Username, err)
	}

	if err := setCachedUserToken(c.user, token.GetUserToken()); err != nil {
		c.log.Debug().Msgf("Failed to cache token for user %s: %v", c.user.Username, err)
	}

	return token.GetUserToken(), nil
}

// Handshake performs the handshake with the k8shelld daemon and ensures the workspace is ready
// It checks the user validity and access to the specified workspace blueprint and starts
// the workspace if it is not running. It also creates an SSH session record in the identity service.
func (c *Connection) Handshake(writer io.Writer, writerOptions *workspace.InfoWriterOptions,
	backends workspace.Backends) (workspace.K8shelldClient, error) {
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

	if c.userStr.BlueprintKind() != userstr.BlueprintKindCustom && !c.user.HasBlueprint(c.userStr.Blueprint()) {
		infoWriter.WriteError(fmt.Sprintf("Access denied: user %s does not have access to blueprint %s.",
			c.user.Username, c.userStr.Blueprint()))
		return nil, fmt.Errorf("user %s does not have access to blueprint %s",
			c.user.Username, c.userStr.Blueprint())
	}

	status, err := workspace.EnsureWorkspace(c.ctx, c.userStr, infoWriter, backends)
	if err != nil {
		if errors.Is(err, workspace.ErrWorkspaceNotFound) || errors.Is(err, workspace.ErrProvisionFailed) {
			infoWriter.WriteError(err.Error())
		} else {
			infoWriter.WriteSystemError(err.Error())
		}
		return nil, fmt.Errorf("failed to ensure workspace for user %s: %w", c.userStr.Username(), err)
	}
	infoWriter.WriteMessage(fmt.Sprintf("Connecting to the workspace at %s...", status.ServerName))

	k8shelld, err := workspace.NewK8shelld(c.k8shelldCfg, status, c.counters, c.user.Username,
		c.connId, c.sessionClient)
	if err != nil {
		infoWriter.WriteSystemError(err.Error())
		return nil, fmt.Errorf("failed to create k8shelld client for user %s: %w", c.user.Username, err)
	}

	c.log.Debug().Msgf("Connecting to k8shelld at %s:%d for user %s, version: %s",
		status.ServerName, status.Port, c.user.Username, status.AppVersion)

	handshake, err := k8shelld.Handshake(c.ctx)
	if err != nil {
		msg := grpcClientMessage(err)
		if s, ok := grpcstatus.FromError(err); ok && s.Code() == grpccodes.Unavailable {
			msg = "The workspace is unreachable. Please retry in a moment."
		}
		infoWriter.WriteSystemError(msg)
		return nil, fmt.Errorf("handshake with k8shelld failed for user %s: %w", c.user.Username, err)
	}
	if !handshake.Accepted {
		infoWriter.WriteSystemError("Connection to the workspace was rejected.")
		return nil, fmt.Errorf("handshake with k8shelld failed for user %s", c.user.Username)
	}

	c.k8shelld = k8shelld
	c.k8shelldVer = status.AppVersion
	c.workspaceName = status.Name

	if c.sessionClient != nil {
		c.reportWg.Add(1)
		go c.reportSessionData()
	}

	return c.k8shelld, nil
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
