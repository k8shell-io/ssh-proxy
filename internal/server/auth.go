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

// AllowedAuthsCallback returns the available authentication methods for the user.
func (s *Server) AllowedAuthsCallback(conn ssh.ConnMetadata) ssh.ServerAuthCallbacks {
	auth := GetAuth(conn)
	s.updateUser(s.ctx, auth)
	return s.getAvailableAuthMethods(auth).Next
}

// AuthPublicKey handles public key authentication.
func (s *Server) AuthPublicKey(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	auth := GetAuth(conn)
	s.updateUser(ctx, auth)
	if auth.User != nil {
		if slices.Contains(auth.User.Auths, "publickey") {
			if s.authPublicKey(auth.User, pubKey) {
				s.log.Info().Msgf("User %s authenticated with public key", auth.User.Username)
				return &ssh.Permissions{}, nil
			} else {
				return nil, fmt.Errorf("public key authentication failed for user %s", auth.Username)
			}
		} else {
			return nil, fmt.Errorf("public key authentication not available for user %s", auth.Username)
		}
	}

	if auth.GetOnboardCap() != nil && auth.GetOnboardCap().CanOnboard {
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
			},
		}
	} else {
		return nil, fmt.Errorf("no available authentication methods for user %s", auth.Username)
	}
}

// AuthPassword handles password authentication.
func (s *Server) AuthPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	auth := GetAuth(conn)
	s.updateUser(ctx, auth)
	if auth.User != nil {
		if slices.Contains(auth.User.Auths, "password") {
			if s.authPassword(auth.User) {
				s.log.Info().Msgf("User %s authenticated with password", auth.User.Username)
				return &ssh.Permissions{}, nil
			} else {
				return nil, fmt.Errorf("password authentication failed for user %s", auth.Username)
			}
		} else {
			return nil, fmt.Errorf("password authentication not available for user %s", auth.Username)
		}
	}

	if auth.GetOnboardCap() != nil && auth.GetOnboardCap().CanOnboard {
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
			},
		}
	} else {
		return nil, fmt.Errorf("no available authentication methods for user %s", auth.Username)
	}
}

// AuthKeyboardInteractive handles keyboard-interactive authentication.
func (s *Server) AuthKeyboardInteractive(conn ssh.ConnMetadata,
	challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	auth := GetAuth(conn)
	s.updateUser(ctx, auth)
	if auth.User != nil {
		return nil, fmt.Errorf("user %s is already onboarded", auth.Username)
	}

	onboardCap := auth.GetOnboardCap()
	if onboardCap == nil {
		return nil, fmt.Errorf("no onboarding capability available for user %s", auth.Username)
	}
	if !onboardCap.CanOnboard {
		s.log.Warn().Msgf("User %s is not allowed to onboard", auth.Username)
		return nil, fmt.Errorf("user %s is not allowed to onboard", auth.Username)
	}

	onboardInfo, err := s.identity.OnboardUser(ctx, auth.Username)
	if err != nil {
		s.log.Error().Msgf("Failed to get onboard info for user %s: %v", auth.Username, err)
		return nil, fmt.Errorf("onboarding failed")
	}
	auth.SetOnboardInfo(onboardInfo)

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
		s.log.Error().Msgf("Failed to get keyboard-interactive response for user %s: %v", auth.Username, err)
		return nil, err
	}

	return s.checkAuthInteractiveResponse(ctx, auth, answers)
}

// checkAuthInteractiveResponse verifies the response from a keyboard-interactive authentication challenge.
func (s *Server) checkAuthInteractiveResponse(ctx context.Context,
	auth *Auth, _ []string) (*ssh.Permissions, error) {
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

// AuthPassword handles password authentication via the identity service.
func (s *Server) authPassword(_ *identity.User) bool {
	// TODO: Call your identity service to validate password
	return false
}

// updateUser fetches user from the identity service and updates user auth
// When the user is not found, it retrieves the user onboarding capability.
func (s *Server) updateUser(ctx context.Context, auth *Auth) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	if auth.User != nil {
		return // User already loaded
	}

	user, err := s.identity.GetUser(ctx, auth.Username)
	if err != nil {
		var eresp identityClient.ErrorResponse
		if errors.As(err, &eresp) && eresp.Status != 404 {
			s.log.Error().Msgf("Failed to get user %s: %v", auth.Username, err)
			return
		}
	}

	if user == nil {
		if auth.OnboardCap == nil {
			var onboardCap *identity.OnboardCapability
			onboardCap, err = s.identity.GetOnboardCapability(ctx, auth.Username)
			if err != nil {
				s.log.Error().Msgf("Failed to get onboarding capability for user %s: %v", auth.Username, err)
				return
			}
			auth.OnboardCap = onboardCap
		}
	} else {
		auth.User = user
	}
}

// getAvailableAuthMethods returns the available authentication methods for the user.
// It returns callbacks for the SSH server authentication process.
func (s *Server) getAvailableAuthMethods(auth *Auth) *ssh.PartialSuccessError {
	if auth.User == nil {
		onboardCap := auth.GetOnboardCap()
		if onboardCap != nil && onboardCap.CanOnboard {
			s.log.Debug().Msgf("User %s is not onboarded, providing keyboard-interactive authentication", auth.Username)
			return &ssh.PartialSuccessError{
				Next: ssh.ServerAuthCallbacks{
					KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
				},
			}
		}
		return nil
	}

	callbacks := ssh.ServerAuthCallbacks{}
	for _, authMethod := range auth.User.Auths {
		switch string(authMethod) {
		case "publickey":
			s.log.Debug().Msgf("Enabling public key authentication for user %s", auth.Username)
			callbacks.PublicKeyCallback = s.AuthPublicKey
		case "password":
			s.log.Debug().Msgf("Enabling password authentication for user %s", auth.Username)
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

	s.log.Warn().Msgf("No available authentication methods for user %s", auth.Username)

	return nil
}
