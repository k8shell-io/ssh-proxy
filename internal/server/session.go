package server

import (
	"encoding/binary"
	"fmt"
	"slices"

	identity "github.com/k8shell-io/identity/pkg/models"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var SSH_AUTH_SOCK_TEMP = "/var/run/ssh-agent-%s.sock"

func (s *Server) handleSessionChannel(sshConn *ssh.ServerConn, connInfo *ConnectionInfo, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Error().Msgf("Failed to accept session channel for user %s: %v", connInfo.User.Username, err)
		return
	}
	defer channel.Close()

	session := &SessionInfo{
		ConnInfo:   connInfo,
		Username:   connInfo.User.Username,
		Env:        []string{},
		SessionId:  fmt.Sprintf("sh-%s-%d", connInfo.proxyID, channel.LocalID()),
		ShellReady: make(chan struct{}),
		TermWidth:  80,
		TermHeight: 24,
	}

	go s.handleSessionRequests(requests, session, channel)

	k8shelld, err := connInfo.CreateK8shelldClient(s.ctx, channel, s.provisioner)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for user %s: %v", session.Username, err)
		return
	}

	<-session.ShellReady

	if session.HasAgent {
		agentChannel, err := s.handleAgent(sshConn, session)
		if err != nil {
			s.log.Error().Msgf("Failed to create agent channel: %v", err)
		}
		defer agentChannel.Close()
	}

	if err := k8shelld.StartShell(s.ctx, channel, session.SessionId,
		session.Env, session.TermWidth, session.TermHeight); err != nil {
		s.log.Error().Msgf("Shell session error: %v", err)
	}
}

func (s *Server) handleSessionRequests(requests <-chan *ssh.Request, session *SessionInfo, channel ssh.Channel) {
	for req := range requests {
		s.log.Debug().Msgf("Received session request: type=%s, want_reply=%t, payload_len=%d",
			req.Type, req.WantReply, len(req.Payload))

		accepted := false
		connInfo := session.ConnInfo

		switch req.Type {
		case "pty-req":
			if connInfo.User.Channels == nil || slices.Contains(connInfo.User.Channels, identity.ChannelPty) {
				if len(req.Payload) >= 8 {
					termLen := binary.BigEndian.Uint32(req.Payload[0:4])

					if len(req.Payload) >= int(4+termLen) {
						termType := string(req.Payload[4 : 4+termLen])
						termEnv := fmt.Sprintf("TERM=%s", termType)
						session.Env = append(session.Env, termEnv)
						s.log.Debug().Msgf("Terminal type: %s for user %s", termType, session.Username)

						offset := 4 + int(termLen)
						if len(req.Payload) >= offset+16 {
							session.TermWidth = binary.BigEndian.Uint32(req.Payload[offset : offset+4])
							session.TermHeight = binary.BigEndian.Uint32(req.Payload[offset+4 : offset+8])

							s.log.Debug().Msgf("PTY size from request: %dx%d for user %s",
								session.TermWidth, session.TermHeight, session.Username)
						}
					}
				}

				session.HasPTY = true
				accepted = true
				s.log.Debug().Msgf("PTY request accepted for user %s", session.Username)
			}

		case "env":
			if len(req.Payload) >= 8 {
				nameLen := binary.BigEndian.Uint32(req.Payload[0:4])

				if len(req.Payload) >= int(4+nameLen+4) {
					name := string(req.Payload[4 : 4+nameLen])
					valueOffset := 4 + nameLen
					valueLen := binary.BigEndian.Uint32(req.Payload[valueOffset : valueOffset+4])
					if len(req.Payload) >= int(8+nameLen+valueLen) {
						value := string(req.Payload[8+nameLen : 8+nameLen+valueLen])
						envVar := fmt.Sprintf("%s=%s", name, value)
						if name != "TERM" || !s.hasTermEnv(session.Env) {
							session.Env = append(session.Env, envVar)
						}

						s.log.Debug().Msgf("Env: %s=%s for user %s", name, value, session.Username)
						accepted = true
					}
				}
			}

			if !accepted {
				s.log.Warn().Msgf("Failed to parse env request payload for user %s", session.Username)
			}

		case "shell":
			if connInfo.User.Channels == nil || slices.Contains(connInfo.User.Channels, identity.ChannelShell) {
				accepted = true
				s.log.Debug().Msgf("Shell request accepted for user %s", session.Username)
			}
			close(session.ShellReady)

		case "window-change":
			k8shelld := session.ConnInfo.k8shelld
			if k8shelld != nil {
				if len(req.Payload) >= 8 {
					accepted = true
					width := binary.BigEndian.Uint32(req.Payload[0:4])
					height := binary.BigEndian.Uint32(req.Payload[4:8])

					s.log.Debug().Msgf("Window change: %dx%d for user %s", width, height, session.Username)
					session.TermWidth = width
					session.TermHeight = height

					if err := k8shelld.ResizeTerminal(s.ctx, session.SessionId, width, height); err != nil {
						s.log.Error().Msgf("Failed to resize terminal: %v", err)
					}
				} else {
					s.log.Warn().Msgf("Received window-change request for user %s, but payload is too short",
						session.Username)
				}
			} else {
				s.log.Warn().Msgf("Received window-change request for user %s, but k8shelld is not available",
					session.Username)
			}

		case "auth-agent-req@openssh.com":
			accepted = true
			session.HasAgent = true
			session.AgentUnixID = fmt.Sprintf("ux-%s-%d", connInfo.proxyID, channel.LocalID())
			session.SSHAuthSock = fmt.Sprintf(SSH_AUTH_SOCK_TEMP, session.AgentUnixID)
			s.log.Debug().Msgf("SSH agent forwarding request accepted for user %s", session.Username)
			session.Env = append(session.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s",
				session.SSHAuthSock))

		default:
			s.log.Warn().Msgf("Unsupported session request type: %s for user %s", req.Type, session.Username)
		}

		if req.WantReply {
			req.Reply(accepted, nil)
		}
	}
}

// Helper function to check if TERM is already set
func (s *Server) hasTermEnv(envVars []string) bool {
	for _, env := range envVars {
		if len(env) >= 5 && env[:5] == "TERM=" {
			return true
		}
	}
	return false
}

// createAgentChannel creates a server-initiated agent forwarding channel and
// handles the communication between the SSH agent and the unix socket in the workspace
func (s *Server) handleAgent(sshConn *ssh.ServerConn, session *SessionInfo) (ssh.Channel, error) {
	s.log.Debug().Msgf("Creating agent channel for user %s", session.Username)

	k8shelld := session.ConnInfo.k8shelld
	if k8shelld == nil {
		return nil, fmt.Errorf("k8shelld client does not exist for user %s", session.Username)
	}

	channel, reqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open agent channel: %w", err)
	}
	go ssh.DiscardRequests(reqs)

	s.log.Debug().Msgf("Agent channel created for user %s", session.Username)

	// handle communication with the SSH agent and the unix socket
	go func() {
		s.log.Debug().Msgf("Starting agent forwarding for user %s, unix socket id: %s", session.Username,
			session.AgentUnixID)
		err := k8shelld.StartUnixSocket(s.ctx, channel, session.AgentUnixID, session.SSHAuthSock)
		if err != nil {
			if statusErr, ok := status.FromError(err); ok && statusErr.Code() == codes.Canceled {
				s.log.Debug().Msgf("Agent forwarding canceled for user %s", session.Username)
			} else {
				s.log.Error().Msgf("Agent forwarding deadline exceeded for user %s", session.Username)
			}
		}
		s.log.Debug().Msgf("Agent channel closed for user %s", session.Username)
	}()

	return channel, nil
}
