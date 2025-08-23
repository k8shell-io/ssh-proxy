package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/k8shell-io/common/models"
	identityClient "github.com/k8shell-io/identity/pkg/client"
	"golang.org/x/crypto/ssh"
)

// AllowedAuthsCallback returns the available authentication methods for the user.
func (s *Server) AllowedAuthsCallback(conn ssh.ConnMetadata) ssh.ServerAuthCallbacks {
	auth, _ := GetConnInfo(conn)
	s.updateUser(s.ctx, auth)
	return s.getAvailableAuthMethods(auth).Next
}

// AuthPublicKey handles public key authentication.
func (s *Server) AuthPublicKey(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	connInfo, err := GetConnInfo(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}
	s.updateUser(ctx, connInfo)
	if connInfo.User != nil {
		if slices.Contains(connInfo.User.Auths, "publickey") {
			if s.authPublicKey(connInfo.User, pubKey) {
				s.log.Info().Msgf("User %s authenticated with public key", connInfo.User.Username)
				return &ssh.Permissions{}, nil
			} else {
				return nil, fmt.Errorf("public key authentication failed for user %s", connInfo.User.Username)
			}
		} else {
			return nil, fmt.Errorf("public key authentication not available for user %s", connInfo.User.Username)
		}
	}

	if connInfo.GetOnboardCap() != nil && connInfo.GetOnboardCap().CanOnboard {
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
			},
		}
	} else {
		return nil, fmt.Errorf("no available authentication methods for user %s", connInfo.UserStr.User)
	}
}

// AuthPassword handles password authentication.
func (s *Server) AuthPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	connInfo, err := GetConnInfo(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}
	s.updateUser(ctx, connInfo)
	if connInfo.User != nil {
		if slices.Contains(connInfo.User.Auths, "password") {
			if s.authPassword(connInfo.User) {
				s.log.Info().Msgf("User %s authenticated with password", connInfo.User.Username)
				return &ssh.Permissions{}, nil
			} else {
				return nil, fmt.Errorf("password authentication failed for user %s", connInfo.User.Username)
			}
		} else {
			return nil, fmt.Errorf("password authentication not available for user %s", connInfo.User.Username)
		}
	}

	if connInfo.GetOnboardCap() != nil && connInfo.GetOnboardCap().CanOnboard {
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
			},
		}
	} else {
		return nil, fmt.Errorf("no available authentication methods for user %s", connInfo.UserStr.User)
	}
}

// AuthKeyboardInteractive handles keyboard-interactive authentication.
func (s *Server) AuthKeyboardInteractive(conn ssh.ConnMetadata,
	challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	connInfo, err := GetConnInfo(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}
	s.updateUser(ctx, connInfo)
	if connInfo.User != nil {
		return nil, fmt.Errorf("user %s is already onboarded", connInfo.UserStr.User)
	}

	onboardCap := connInfo.GetOnboardCap()
	if onboardCap == nil {
		return nil, fmt.Errorf("no onboarding capability available for user %s", connInfo.UserStr.User)
	}
	if !onboardCap.CanOnboard {
		s.log.Warn().Msgf("User %s is not allowed to onboard", connInfo.UserStr.User)
		return nil, fmt.Errorf("user %s is not allowed to onboard", connInfo.UserStr.User)
	}

	onboardInfo, err := s.identity.OnboardUser(ctx, connInfo.UserStr.User)
	if err != nil {
		s.log.Error().Msgf("Failed to get onboard info for user %s: %v", connInfo.UserStr.User, err)
		return nil, fmt.Errorf("onboarding failed")
	}
	connInfo.SetOnboardInfo(onboardInfo)

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
		s.log.Error().Msgf("Failed to get keyboard-interactive response for user %s: %v", connInfo.UserStr.User, err)
		return nil, err
	}

	return s.checkAuthInteractiveResponse(ctx, connInfo, answers)
}

// checkAuthInteractiveResponse verifies the response from a keyboard-interactive authentication challenge.
func (s *Server) checkAuthInteractiveResponse(ctx context.Context,
	auth *ConnectionInfo, _ []string) (*ssh.Permissions, error) {
	onboardInfo := auth.GetOnboardInfo()
	if onboardInfo == nil {
		return nil, fmt.Errorf("no onboard info available")
	}

	s.log.Info().Msgf("Checking onboarding status for user %s", onboardInfo.Username)
	s.updateUser(ctx, auth)
	if auth.User == nil {
		return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{KeyboardInteractiveCallback: s.AuthKeyboardInteractive}}
	}

	s.log.Info().Msgf("Onboarding completed for user %s", onboardInfo.Username)
	return nil, s.getAvailableAuthMethods(auth)
}

// AuthPublicKey handles public key authentication via the identity service.
func (s *Server) authPublicKey(user *models.User, pubKey ssh.PublicKey) bool {
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

// AuthPassword handles password authentication via the identity service.
func (s *Server) authPassword(_ *models.User) bool {
	// TODO: Call your identity service to validate password
	return false
}

// updateUser fetches user from the identity service and updates user auth
// When the user is not found, it retrieves the user onboarding capability.
func (s *Server) updateUser(ctx context.Context, connInfo *ConnectionInfo) {
	connInfo.mu.Lock()
	defer connInfo.mu.Unlock()

	if connInfo.User != nil {
		return // User already loaded
	}

	user, err := s.identity.GetUser(ctx, connInfo.UserStr.User)
	if err != nil {
		var eresp identityClient.ErrorResponse
		if errors.As(err, &eresp) && eresp.Status != 404 {
			s.log.Error().Msgf("Failed to get user %s: %v", connInfo.UserStr.User, err)
			return
		}
	}

	if user == nil {
		if connInfo.OnboardCap == nil {
			var onboardCap *models.OnboardCapability
			onboardCap, err = s.identity.GetOnboardCapability(ctx, connInfo.UserStr.User)
			if err != nil {
				s.log.Error().Msgf("Failed to get onboarding capability for user %s: %v", connInfo.UserStr.User, err)
				return
			}
			connInfo.OnboardCap = onboardCap
		}
	} else {
		connInfo.User = user
	}
}

// getAvailableAuthMethods returns the available authentication methods for the user.
// It returns callbacks for the SSH server authentication process.
func (s *Server) getAvailableAuthMethods(connInfo *ConnectionInfo) *ssh.PartialSuccessError {
	if connInfo.User == nil {
		onboardCap := connInfo.GetOnboardCap()
		if onboardCap != nil && onboardCap.CanOnboard {
			s.log.Debug().Msgf("User %s is not onboarded, providing keyboard-interactive authentication",
				connInfo.UserStr.User)
			return &ssh.PartialSuccessError{
				Next: ssh.ServerAuthCallbacks{
					KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
				},
			}
		}
		return nil
	}

	callbacks := ssh.ServerAuthCallbacks{}
	for _, authMethod := range connInfo.User.Auths {
		switch string(authMethod) {
		case "publickey":
			s.log.Debug().Msgf("Enabling public key authentication for user %s", connInfo.User.Username)
			callbacks.PublicKeyCallback = s.AuthPublicKey
		case "password":
			s.log.Debug().Msgf("Enabling password authentication for user %s", connInfo.User.Username)
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

	s.log.Warn().Msgf("No available authentication methods for user %s", connInfo.UserStr.User)

	return nil
}
