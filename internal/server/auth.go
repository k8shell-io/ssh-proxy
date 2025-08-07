package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	identityClient "github.com/k8shell-io/identity/pkg/client"
	identity "github.com/k8shell-io/identity/pkg/models"
	"golang.org/x/crypto/ssh"
)

func (s *Server) AllowedAuthsCallback(conn ssh.ConnMetadata) ssh.ServerAuthCallbacks {
	state := GetState(conn)
	s.updateUser(s.ctx, state)
	return s.getAvailableAuthMethods(state).Next
}

func (s *Server) AuthPublicKey(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	state := GetState(conn)
	s.updateUser(ctx, state)
	if state.User != nil {
		if slices.Contains(state.User.Auths, "publickey") {
			if s.authPublicKey(state.User, pubKey) {
				s.log.Info().Msgf("User %s authenticated with public key", state.User.Username)
				return &ssh.Permissions{}, nil
			} else {
				return nil, fmt.Errorf("public key authentication failed for user %s", state.Username)
			}
		} else {
			return nil, fmt.Errorf("public key authentication not available for user %s", state.Username)
		}
	}

	if state.GetOnboardCap() != nil && state.GetOnboardCap().CanOnboard {
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
			},
		}
	} else {
		return nil, fmt.Errorf("no available authentication methods for user %s", state.Username)
	}
}

func (s *Server) AuthPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	state := GetState(conn)
	s.updateUser(ctx, state)
	if state.User != nil {
		if slices.Contains(state.User.Auths, "password") {
			if s.authPassword(state.User) {
				s.log.Info().Msgf("User %s authenticated with password", state.User.Username)
				return &ssh.Permissions{}, nil
			} else {
				return nil, fmt.Errorf("password authentication failed for user %s", state.Username)
			}
		} else {
			return nil, fmt.Errorf("password authentication not available for user %s", state.Username)
		}
	}

	if state.GetOnboardCap() != nil && state.GetOnboardCap().CanOnboard {
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
			},
		}
	} else {
		return nil, fmt.Errorf("no available authentication methods for user %s", state.Username)
	}
}

func (s *Server) AuthKeyboardInteractive(conn ssh.ConnMetadata,
	challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	state := GetState(conn)
	s.updateUser(ctx, state)
	if state.User != nil {
		return nil, fmt.Errorf("user %s is already onboarded", state.Username)
	}

	onboardCap := state.GetOnboardCap()
	if onboardCap == nil {
		return nil, fmt.Errorf("no onboarding capability available for user %s", state.Username)
	}
	if !onboardCap.CanOnboard {
		s.log.Warn().Msgf("User %s is not allowed to onboard", state.Username)
		return nil, fmt.Errorf("user %s is not allowed to onboard", state.Username)
	}

	onboardInfo, err := s.identity.OnboardUser(ctx, state.Username)
	if err != nil {
		s.log.Error().Msgf("Failed to get onboard info for user %s: %v", state.Username, err)
		return nil, fmt.Errorf("onboarding failed")
	}
	state.SetOnboardInfo(onboardInfo)

	prompt := fmt.Sprintf(
		"Onboarding user %s via %s.\n"+
			"To continue, visit: %s\n"+
			"and enter the code: %s\n"+
			"(Valid for %d seconds).\n\n"+
			"After onboarding, you will authenticate using your SSH key only.\n"+
			"Press <Enter> to continue or <Ctrl+C> to cancel.\n",
		onboardInfo.Username,
		onboardInfo.Provider,
		onboardInfo.VerificationUrl,
		onboardInfo.UserCode,
		onboardInfo.ExpiresIn,
	)

	answers, err := challenge("", "", []string{prompt}, []bool{true})
	if err != nil {
		s.log.Error().Msgf("Failed to get keyboard-interactive response for user %s: %v", state.Username, err)
		return nil, err
	}

	return s.checkAuthInteractiveResponse(ctx, state, answers)
}

func (s *Server) checkAuthInteractiveResponse(ctx context.Context,
	state *State, _ []string) (*ssh.Permissions, error) {
	onboardInfo := state.GetOnboardInfo()
	if onboardInfo == nil {
		return nil, fmt.Errorf("no onboard info available")
	}

	s.log.Info().Msgf("Checking onboarding status for user %s", onboardInfo.Username)
	s.updateUser(ctx, state)
	if state.User == nil {
		return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{KeyboardInteractiveCallback: s.AuthKeyboardInteractive}}
	}

	s.log.Info().Msgf("Onboarding completed for user %s", onboardInfo.Username)
	return nil, s.getAvailableAuthMethods(state)
}

func (s *Server) authPublicKey(user *identity.User, pubKey ssh.PublicKey) bool {
	pubKeyString := string(ssh.MarshalAuthorizedKey(pubKey))
	pubKeyString = strings.TrimSuffix(pubKeyString, "\n")
	pubKeyHash := ssh.FingerprintSHA256(pubKey)

	s.log.Debug().Msgf("Authenticating user %s with public key: %s", user.Username, pubKeyHash)
	authResponse, err := s.identity.AuthPublicKey(s.ctx, user.Username, pubKeyString)
	if err != nil || authResponse == nil {
		s.log.Error().Msgf("Failed to get authentication response for user %s: %v", user.Username, err)
		return false
	}

	if !authResponse.Authenticated {
		s.log.Warn().Msgf("Public key authentication failed for user %s", user.Username)
		return false
	}
	return true
}

func (s *Server) authPassword(_ *identity.User) bool {
	// TODO: Call your identity service to validate password
	return false
}

// updateUser fetches user information and updates auth state
func (s *Server) updateUser(ctx context.Context, state *State) {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.User != nil {
		return // User already loaded
	}

	user, err := s.identity.GetUser(ctx, state.Username)
	if err != nil {
		var eresp identityClient.ErrorResponse
		if errors.As(err, &eresp) && eresp.Status != 404 {
			s.log.Error().Msgf("Failed to get user %s: %v", state.Username, err)
			return
		}
	}

	if user == nil {
		if state.OnboardCap == nil {
			var onboardCap *identity.OnboardCapability
			onboardCap, err = s.identity.GetOnboardCapability(ctx, state.Username)
			if err != nil {
				s.log.Error().Msgf("Failed to get onboarding capability for user %s: %v", state.Username, err)
				return
			}
			state.OnboardCap = onboardCap
		}
	} else {
		state.User = user
	}
}

func (s *Server) getAvailableAuthMethods(state *State) *ssh.PartialSuccessError {
	if state.User == nil {
		onboardCap := state.GetOnboardCap()
		if onboardCap != nil && onboardCap.CanOnboard {
			s.log.Debug().Msgf("User %s is not onboarded, providing keyboard-interactive authentication", state.Username)
			return &ssh.PartialSuccessError{
				Next: ssh.ServerAuthCallbacks{
					KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
				},
			}
		}
		return nil
	}

	callbacks := ssh.ServerAuthCallbacks{}
	for _, authMethod := range state.User.Auths {
		switch string(authMethod) {
		case "publickey":
			s.log.Debug().Msgf("Enabling public key authentication for user %s", state.Username)
			callbacks.PublicKeyCallback = s.AuthPublicKey
		case "password":
			s.log.Debug().Msgf("Enabling password authentication for user %s", state.Username)
			callbacks.PasswordCallback = s.AuthPassword
		}
	}

	if callbacks.PublicKeyCallback != nil ||
		callbacks.PasswordCallback != nil ||
		callbacks.KeyboardInteractiveCallback != nil {
		return &ssh.PartialSuccessError{
			Next: callbacks,
		}
	}

	s.log.Warn().Msgf("No available authentication methods for user %s", state.Username)

	return nil
}
