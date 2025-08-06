package server

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func (s *Server) AuthPublicKey(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	s.log.Info().Msgf("SSH public key authentication attempt, user: %s, key type: %s", conn.User(), pubKey.Type())
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	user, err := s.identity.GetUser(ctx, conn.User())
	if err != nil {
		s.log.Error().Err(err).Msgf("Failed to get user %s from identity service", conn.User())
		return nil, err
	}

	if user == nil {
		s.log.Warn().Msgf("User %s not found in identity service", conn.User())
		return nil, fmt.Errorf("user not found: %s", conn.User())
	}

	return &ssh.Permissions{}, nil
}

func (s *Server) AuthPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	s.log.Info().Msgf("SSH password authentication attempt, user: %s", conn.User())
	return &ssh.Permissions{}, nil
}
