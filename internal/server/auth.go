package server

import "golang.org/x/crypto/ssh"

func (s *Server) AuthPublicKey(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	s.log.Info().Msgf("SSH public key authentication attempt, user: %s, key type: %s", conn.User(), pubKey.Type())
	return &ssh.Permissions{}, nil
}

func (s *Server) AuthPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	s.log.Info().Msgf("SSH password authentication attempt, user: %s", conn.User())
	return &ssh.Permissions{}, nil
}
