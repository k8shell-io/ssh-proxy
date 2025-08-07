package server

import (
	"fmt"
	"strings"
	"sync"
	"time"

	identity "github.com/k8shell-io/identity/pkg/models"
	"golang.org/x/crypto/ssh"
)

type SessionInfo struct {
	Username     string
	TermType     string
	TermWidth    uint32
	TermHeight   uint32
	TermWidthPx  uint32
	TermHeightPx uint32
	Environment  map[string]string
	Command      string
	HasPTY       bool
}

// State represents the authentication state for a connection
type State struct {
	Username        string
	OnboardCap      *identity.OnboardCapability
	OnboardInfo     *identity.OnboardUser
	User            *identity.User
	AuthFailCount   int
	AuthLastAttempt time.Time
	mu              sync.RWMutex
	Session         *SessionInfo
}

// Global state storage
var authStates = make(map[string]*State)
var authStatesMutex sync.RWMutex

func getConnectionID(conn ssh.ConnMetadata) (string, string) {
	username := strings.Split(conn.User(), "~")[0]
	connID := fmt.Sprintf("12345-%s", username)
	return username, connID
}

func GetState(conn ssh.ConnMetadata) *State {
	username, connID := getConnectionID(conn)

	authStatesMutex.RLock()
	defer authStatesMutex.RUnlock()
	state := authStates[connID]
	if state == nil {
		state = &State{
			Username: username,
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
