package server

import (
	"fmt"
	"strings"
	"sync"
	"time"

	identity "github.com/k8shell-io/identity/pkg/models"
	"github.com/k8shell-io/ssh-proxy/internal/k8shelld"
	"golang.org/x/crypto/ssh"
)

// ConnectionInfo represents the connection information for a user
type ConnectionInfo struct {
	k8shelld        *k8shelld.Client            // k8shelld client for interacting with the workspace k8shelld daemon
	Username        string                      // username of the user
	BlueprintName   string                      // name of the blueprint
	OnboardCap      *identity.OnboardCapability // onboarding capabilities
	OnboardInfo     *identity.OnboardUser       // onboarding information
	User            *identity.User              // user information
	AuthFailCount   int                         // number of failed authentication attempts
	AuthLastAttempt time.Time                   // timestamp of the last authentication attempt
	mu              sync.RWMutex                // mutex for synchronizing access
}

// SessionInfo holds information about a user's SSH session
type SessionInfo struct {
	ConnInfo     *ConnectionInfo // connection information
	Username     string          // username of the user
	TermType     string          // terminal type
	TermWidth    uint32          // terminal width
	TermHeight   uint32          // terminal height
	TermWidthPx  uint32          // terminal width in pixels
	TermHeightPx uint32          // terminal height in pixels
	Env          []string        // environment variables
	Command      string          // command to execute
	HasPTY       bool            // true when the session has a pseudo-terminal
	SessionId    string          // unique session identifier
	ShellReady   chan struct{}   // channel to signal when the shell is ready
	HasAgent     bool            // true when the session has an SSH agent
	AgentChannel ssh.Channel     // channel for the SSH agent
}

// Global state storage
var connStates = make(map[string]*ConnectionInfo)
var connStatesMutex sync.RWMutex

func getConnectionID(conn ssh.ConnMetadata) (string, string, string) {
	var username, bpname string
	parsed := strings.Split(conn.User(), "~")
	if len(parsed) >= 2 {
		username = parsed[0]
		bpname = parsed[1]
	}
	if len(parsed) == 1 {
		username = parsed[0]
		bpname = "dev"
	}

	connID := fmt.Sprintf("%s-%s", conn.RemoteAddr(), username)
	return username, bpname, connID
}

func RemoveState(state *ConnectionInfo) {
	connStatesMutex.Lock()
	defer connStatesMutex.Unlock()
	delete(connStates, fmt.Sprintf("12345-%s", state.Username))
}

func GetConnInfo(conn ssh.ConnMetadata) *ConnectionInfo {
	username, blueprintName, connID := getConnectionID(conn)

	connStatesMutex.RLock()
	defer connStatesMutex.RUnlock()
	connInfo := connStates[connID]
	if connInfo == nil {
		connInfo = &ConnectionInfo{
			Username:      username,
			BlueprintName: blueprintName,
		}
		connStates[connID] = connInfo
	}
	return connInfo
}

func (s *ConnectionInfo) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.k8shelld != nil {
		s.k8shelld.Close()
		s.k8shelld = nil
	}
}

func (s *ConnectionInfo) SetOnboardInfo(onboardInfo *identity.OnboardUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OnboardInfo = onboardInfo
}

func (s *ConnectionInfo) GetOnboardInfo() *identity.OnboardUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OnboardInfo
}

func (s *ConnectionInfo) SetOnboardCap(onboardCap *identity.OnboardCapability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OnboardCap = onboardCap
}

func (s *ConnectionInfo) GetOnboardCap() *identity.OnboardCapability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OnboardCap
}
