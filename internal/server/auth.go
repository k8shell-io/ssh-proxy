// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
	"golang.org/x/crypto/ssh"
)

// AllowedAuthsCallback returns the available authentication methods for the user.
func (s *Server) AllowedAuthsCallback(conn ssh.ConnMetadata) ssh.ServerAuthCallbacks {
	connInfo, err := s.GetConnInfo(conn)
	if err != nil {
		s.log.Error().Msgf("Failed to get connection info: %v", err)
		return ssh.ServerAuthCallbacks{}
	}
	s.updateUser(s.ctx, connInfo)
	authMethods := s.getAvailableAuthMethods(connInfo)
	if authMethods == nil {
		return ssh.ServerAuthCallbacks{}
	}
	return authMethods.Next
}

// AuthPublicKey handles public key authentication.
func (s *Server) AuthPublicKey(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	connInfo, err := s.GetConnInfo(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}
	s.updateUser(ctx, connInfo)
	if connInfo.user != nil {
		if slices.Contains(connInfo.user.Auths, "publickey") {
			if s.authPublicKey(connInfo.user, pubKey) {
				s.log.Info().Msgf("User %s authenticated with public key", connInfo.user.Username)
				return &ssh.Permissions{}, nil
			} else {
				connInfo.AddFailureInfo("Public key authentication failed", nil)
				return nil, fmt.Errorf("public key authentication failed for user %s", connInfo.user.Username)
			}
		} else {
			connInfo.AddFailureInfo("Public key authentication not available", nil)
			return nil, fmt.Errorf("public key authentication not available for user %s", connInfo.user.Username)
		}
	}

	if connInfo.GetOnboardCap() != nil && connInfo.GetOnboardCap().CanOnboard {
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
			},
		}
	} else {
		connInfo.AddFailureInfo("No available authentication methods", nil)
		return nil, fmt.Errorf("no available authentication methods for user %s", connInfo.userStr.Username)
	}
}

// AuthPassword handles password authentication.
func (s *Server) AuthPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	connInfo, err := s.GetConnInfo(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}
	s.updateUser(ctx, connInfo)
	if connInfo.user != nil {
		if slices.Contains(connInfo.user.Auths, "password") {
			if s.authPassword(connInfo.user) {
				s.log.Info().Msgf("User %s authenticated with password", connInfo.user.Username)
				return &ssh.Permissions{}, nil
			} else {
				connInfo.AddFailureInfo("Password authentication failed", nil)
				return nil, fmt.Errorf("password authentication failed for user %s", connInfo.user.Username)
			}
		} else {
			connInfo.AddFailureInfo("Password authentication not available", nil)
			return nil, fmt.Errorf("password authentication not available for user %s", connInfo.user.Username)
		}
	}

	if connInfo.GetOnboardCap() != nil && connInfo.GetOnboardCap().CanOnboard {
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
			},
		}
	} else {
		connInfo.AddFailureInfo("No available authentication methods", nil)
		return nil, fmt.Errorf("no available authentication methods for user %s", connInfo.userStr.Username)
	}
}

// AuthKeyboardInteractive handles keyboard-interactive authentication.
func (s *Server) AuthKeyboardInteractive(conn ssh.ConnMetadata,
	challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	connInfo, err := s.GetConnInfo(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}
	s.updateUser(ctx, connInfo)
	if connInfo.user != nil {
		return nil, fmt.Errorf("user %s is already onboarded", connInfo.userStr.Username)
	}

	onboardCap := connInfo.GetOnboardCap()
	if onboardCap == nil {
		return nil, fmt.Errorf("no onboarding capability available for user %s", connInfo.userStr.Username)
	}
	if !onboardCap.CanOnboard {
		s.log.Warn().Msgf("User %s is not allowed to onboard", connInfo.userStr.Username)
		return nil, fmt.Errorf("user %s is not allowed to onboard", connInfo.userStr.Username)
	}

	onboardInfo, err := s.identity.OnboardUserDeviceFlow(ctx,
		&identitypb.Username{Username: connInfo.userStr.Username})
	if err != nil {
		s.log.Error().Msgf("Failed to get onboard info for user %s: %v", connInfo.userStr.Username, err)
		return nil, fmt.Errorf("onboarding failed")
	}
	connInfo.SetOnboardInfo(gapi.ProtoToOnboardUserDeviceFlow(onboardInfo))

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
		s.log.Error().Msgf("Failed to get keyboard-interactive response for user %s: %v",
			connInfo.userStr.Username, err)
		return nil, err
	}

	return s.checkAuthInteractiveResponse(ctx, connInfo, answers)
}

// checkAuthInteractiveResponse verifies the response from a keyboard-interactive authentication challenge.
func (s *Server) checkAuthInteractiveResponse(ctx context.Context,
	auth *Connection, _ []string) (*ssh.Permissions, error) {
	onboardInfo := auth.GetOnboardInfo()
	if onboardInfo == nil {
		return nil, fmt.Errorf("no onboard info available")
	}

	s.log.Info().Msgf("Checking onboarding status for user %s", onboardInfo.Username)
	s.updateUser(ctx, auth)
	if auth.user == nil {
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
	authResponse, err := s.identity.AuthUserPublicKey(s.ctx, &identitypb.AuthUserPublicKeyRequest{
		Username: user.Username, PublicKey: pubKeyString})
	if err != nil || authResponse == nil {
		s.log.Error().Msgf("Failed to get authentication response for user %s: %v", user.Username, err)
		return false
	}

	if !authResponse.Valid {
		s.log.Warn().Msgf("Public key authentication failed for user %s", user.Username)
		return false
	}
	return true
}

// AuthPassword handles password authentication via the identity service.
func (s *Server) authPassword(_ *models.User) bool {
	// TODO: Call identity service to validate password
	return false
}

// updateUser fetches user from the identity service and updates user auth
// When the user is not found, it retrieves the user onboarding capability.
func (s *Server) updateUser(ctx context.Context, connInfo *Connection) {
	connInfo.mu.Lock()
	defer connInfo.mu.Unlock()

	if connInfo.user != nil {
		return // User already loaded
	}

	user, err := s.identity.FindUser(ctx, &identitypb.FindUserRequest{Username: connInfo.userStr.Username})
	if err != nil {
		connInfo.AddFailureInfo("Failed to get user", err)
	}

	if user == nil {
		if connInfo.onboardCap == nil {
			onboardCap, err := s.identity.GetUserOnboardCapability(ctx, &identitypb.Username{
				Username: connInfo.userStr.Username})
			if err != nil {
				s.log.Error().Msgf("Failed to get onboarding capability for user %s: %v",
					connInfo.userStr.Username, err)
				return
			}
			connInfo.onboardCap = gapi.ProtoToUserOnboardCapability(onboardCap)
			if onboardCap == nil || !onboardCap.CanOnboard {
				s.log.Warn().Msgf("User %s is not onboarded and has no onboarding capability", connInfo.userStr.Username)
				connInfo.AddFailureInfo("User is not onboarded and has no onboarding capability", nil)
			}
		}
	} else {
		connInfo.user = gapi.ProtoToUser(user)
	}
}

// getAvailableAuthMethods returns the available authentication methods for the user.
// It returns callbacks for the SSH server authentication process.
func (s *Server) getAvailableAuthMethods(connInfo *Connection) *ssh.PartialSuccessError {
	if connInfo.user == nil {
		onboardCap := connInfo.GetOnboardCap()
		if onboardCap != nil && onboardCap.CanOnboard {
			s.log.Debug().Msgf("User %s is not onboarded, providing keyboard-interactive authentication",
				connInfo.userStr.Username)
			return &ssh.PartialSuccessError{
				Next: ssh.ServerAuthCallbacks{
					KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
				},
			}
		}
		return nil
	}

	callbacks := ssh.ServerAuthCallbacks{}
	for _, authMethod := range connInfo.user.Auths {
		switch string(authMethod) {
		case "publickey":
			s.log.Debug().Msgf("Enabling public key authentication for user %s", connInfo.user.Username)
			callbacks.PublicKeyCallback = s.AuthPublicKey
		case "password":
			s.log.Debug().Msgf("Enabling password authentication for user %s", connInfo.user.Username)
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

	s.log.Warn().Msgf("No available authentication methods for user %s", connInfo.userStr.Username)
	connInfo.AddFailureInfo("No available authentication methods", nil)

	return nil
}
