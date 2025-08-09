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

type SessionInfo struct {
	State        *State
	Username     string
	TermType     string
	TermWidth    uint32
	TermHeight   uint32
	TermWidthPx  uint32
	TermHeightPx uint32
	Env          []string
	Command      string
	HasPTY       bool
	k8shelld     *k8shelld.Client
	ShellReady   chan struct{}
	SessionId    string
}

// State represents the authentication state for a connection
type State struct {
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
var authStates = make(map[string]*State)
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

	connID := fmt.Sprintf("12345-%s", username)
	return username, bpname, connID
}

func RemoveState(state *State) {
	authStatesMutex.Lock()
	defer authStatesMutex.Unlock()
	delete(authStates, fmt.Sprintf("12345-%s", state.Username))
}

func GetState(conn ssh.ConnMetadata) *State {
	username, bpname, connID := getConnectionID(conn)

	authStatesMutex.RLock()
	defer authStatesMutex.RUnlock()
	state := authStates[connID]
	if state == nil {
		state = &State{
			Username: username,
			BpName:   bpname,
		}
		authStates[connID] = state
	}
	return state
}

func (s *State) SetOnboardInfo(onboardInfo *identity.OnboardUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OnboardInfo = onboardInfo
}

func (s *State) GetOnboardInfo() *identity.OnboardUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OnboardInfo
}

func (s *State) SetOnboardCap(onboardCap *identity.OnboardCapability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OnboardCap = onboardCap
}

func (s *State) GetOnboardCap() *identity.OnboardCapability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OnboardCap
}
