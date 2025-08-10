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

// SessionInfo holds information about a user's SSH session
type SessionInfo struct {
	k8shelld     *k8shelld.Client // k8shelld client for interacting with the workspace k8shelld daemon
	Auth         *Auth            // authentication state
	Username     string           // username of the user
	TermType     string           // terminal type
	TermWidth    uint32           // terminal width
	TermHeight   uint32           // terminal height
	TermWidthPx  uint32           // terminal width in pixels
	TermHeightPx uint32           // terminal height in pixels
	Env          []string         // environment variables
	Command      string           // command to execute
	HasPTY       bool             // true when the session has a pseudo-terminal
	SessionId    string           // unique session identifier
	ShellReady   chan struct{}    // channel to signal when the shell is ready
	HasAgent     bool             // true when the session has an SSH agent
	AgentChannel ssh.Channel      // channel for the SSH agent
}

// Auth represents the authentication state for a connection
type Auth struct {
	Username        string
	BpName          string
	OnboardCap      *identity.OnboardCapability
	OnboardInfo     *identity.OnboardUser
	User            *identity.User
	AuthFailCount   int
	AuthLastAttempt time.Time
	mu              sync.RWMutex
}

// Global state storage
var authStates = make(map[string]*Auth)
var authStatesMutex sync.RWMutex

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

func RemoveState(state *Auth) {
	authStatesMutex.Lock()
	defer authStatesMutex.Unlock()
	delete(authStates, fmt.Sprintf("12345-%s", state.Username))
}

func GetAuth(conn ssh.ConnMetadata) *Auth {
	username, bpname, connID := getConnectionID(conn)

	authStatesMutex.RLock()
	defer authStatesMutex.RUnlock()
	auth := authStates[connID]
	if auth == nil {
		auth = &Auth{
			Username: username,
			BpName:   bpname,
		}
		authStates[connID] = auth
	}
	return auth
}

func (s *Auth) SetOnboardInfo(onboardInfo *identity.OnboardUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OnboardInfo = onboardInfo
}

func (s *Auth) GetOnboardInfo() *identity.OnboardUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OnboardInfo
}

func (s *Auth) SetOnboardCap(onboardCap *identity.OnboardCapability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OnboardCap = onboardCap
}

func (s *Auth) GetOnboardCap() *identity.OnboardCapability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OnboardCap
}
