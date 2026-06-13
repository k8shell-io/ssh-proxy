// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var SSH_AUTH_SOCK_TEMP = "/var/run/ssh-agent-%s.sock"

func (s *Server) handleSessionChannel(sshConn *ssh.ServerConn, connInfo *Connection, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Error().Msgf("Failed to accept session channel for user %s: %v", connInfo.user.Username, err)
		return
	}
	defer channel.Close()

	session := &Session{
		username:   connInfo.user.Username,
		env:        []string{},
		sessionId:  fmt.Sprintf("sh-%s%d", connInfo.connId, connInfo.SeqNumber()),
		termWidth:  80,
		termHeight: 24,
		hasPTY:     false,
	}
	connInfo.session = session

	sessionType := make(chan string, 2)
	go s.handleSessionRequests(requests, connInfo, channel, sessionType)

	sType := <-sessionType

	switch sType {
	case "shell":
		s.handleShellRequest(sshConn, connInfo, channel)

	case "sftp":
		s.handleSFTPSubsystem(sshConn, connInfo, channel)

	case "exec":
		s.handleExecRequest(connInfo, channel)

	default:
		s.log.Warn().Msgf("No valid session request received for user %s", session.username)
	}
}

func (s *Server) handleSessionRequests(requests <-chan *ssh.Request, connInfo *Connection,
	_ ssh.Channel, sessionType chan<- string) {
	sessionTypeSent := false
	session := connInfo.session

	for req := range requests {
		s.log.Debug().Msgf("Received session request: type=%s, want_reply=%t, payload_len=%d",
			req.Type, req.WantReply, len(req.Payload))

		accepted := false
		switch req.Type {
		case "subsystem":
			if len(req.Payload) < 4 {
				err := req.Reply(false, nil)
				if err != nil {
					s.log.Error().Msgf("Failed to reply to subsystem request: %v", err)
				}
				continue
			}

			nameLen := uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 |
				uint32(req.Payload[2])<<8 | uint32(req.Payload[3])
			if len(req.Payload) < int(4+nameLen) {
				err := req.Reply(false, nil)
				if err != nil {
					s.log.Error().Msgf("Failed to reply to subsystem request: %v", err)
				}
				continue
			}

			subsystemName := string(req.Payload[4 : 4+nameLen])
			s.log.Debug().Msgf("Subsystem request: %s", subsystemName)

			if subsystemName == "sftp" {
				err := req.Reply(true, nil)
				if err != nil {
					s.log.Error().Msgf("Failed to reply to subsystem request: %v", err)
				}
				connInfo.AddChannelInfo(models.ChannelShortSf)
				sessionType <- "sftp"
				sessionTypeSent = true
			} else {
				s.log.Warn().Msgf("Unsupported subsystem: %s", subsystemName)
				err := req.Reply(false, nil)
				if err != nil {
					s.log.Error().Msgf("Failed to reply to subsystem request: %v", err)
				}
			}
		case "pty-req":
			if len(req.Payload) >= 8 {
				termLen := binary.BigEndian.Uint32(req.Payload[0:4])

				if len(req.Payload) >= int(4+termLen) {
					termType := string(req.Payload[4 : 4+termLen])
					termEnv := fmt.Sprintf("TERM=%s", termType)
					session.env = append(session.env, termEnv)
					s.log.Debug().Msgf("Terminal type: %s for user %s", termType, session.username)

					offset := 4 + int(termLen)
					if len(req.Payload) >= offset+16 {
						session.termWidth = binary.BigEndian.Uint32(req.Payload[offset : offset+4])
						session.termHeight = binary.BigEndian.Uint32(req.Payload[offset+4 : offset+8])

						s.log.Debug().Msgf("PTY size from request: %dx%d for user %s",
							session.termWidth, session.termHeight, session.username)
					}
				}
			}

			session.hasPTY = true
			accepted = true
			connInfo.AddChannelInfo(models.ChannelShortPt)
			s.log.Debug().Msgf("PTY request accepted for user %s", session.username)

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
						if name != "TERM" || !s.hasTermEnv(session.env) {
							session.env = append(session.env, envVar)
						}

						s.log.Debug().Msgf("Env: %s=%s for user %s", name, value, session.username)
						accepted = true
					}
				}
			}

			if !accepted {
				s.log.Warn().Msgf("Failed to parse env request payload for user %s", session.username)
			}

		case "shell":
			accepted = true
			s.log.Debug().Msgf("Shell request accepted for user %s", session.username)
			sessionType <- "shell"
			sessionTypeSent = true
			connInfo.AddChannelInfo(models.ChannelShortSh)

		case "exec":
			command, err := s.parseExecRequest(req.Payload)
			if err != nil {
				s.log.Error().Msgf("Failed to parse exec request: %v", err)
			} else {
				accepted = true
				session.command = command
				s.log.Debug().Msgf("Exec request accepted for user %s: %s", session.username, command)
				sessionType <- "exec"
				sessionTypeSent = true
				connInfo.AddChannelInfo(models.ChannelShortEx)
			}

		case "signal":
			if len(req.Payload) < 4 {
				err := req.Reply(false, nil)
				if err != nil {
					s.log.Error().Msgf("Failed to reply to signal request: %v", err)
				}
				continue
			}

			nameLen := binary.BigEndian.Uint32(req.Payload[0:4])
			if len(req.Payload) < int(4+nameLen) {
				err := req.Reply(false, nil)
				if err != nil {
					s.log.Error().Msgf("Failed to reply to signal request: %v", err)
				}
				continue
			}

			signalName := string(req.Payload[4 : 4+nameLen])
			s.log.Debug().Msgf("Signal request: %s", signalName)

			if session.signalChan != nil {
				select {
				case session.signalChan <- signalName:
					accepted = true
					s.log.Debug().Msgf("Signal %s sent to active exec process for user %s", signalName, session.username)
				default:
					s.log.Warn().Msgf("Signal channel full, couldn't send signal %s for user %s", signalName, session.username)
					accepted = false
				}
			} else {
				s.log.Warn().Msgf("No active exec session to send signal %s for user %s", signalName, session.username)
				accepted = false
			}

		case "window-change":
			k8shelld := connInfo.k8shelld
			if k8shelld != nil {
				if len(req.Payload) >= 8 {
					accepted = true
					width := binary.BigEndian.Uint32(req.Payload[0:4])
					height := binary.BigEndian.Uint32(req.Payload[4:8])

					s.log.Debug().Msgf("Window change: %dx%d for user %s", width, height, session.username)
					session.termWidth = width
					session.termHeight = height

					if err := k8shelld.ResizeTerminal(connInfo.ctx, session.sessionId, width, height); err != nil {
						s.log.Error().Msgf("Failed to resize terminal: %v", err)
					}
				} else {
					s.log.Warn().Msgf("Received window-change request for user %s, but payload is too short",
						session.username)
				}
			} else {
				s.log.Warn().Msgf("Received window-change request for user %s, but k8shelld is not available",
					session.username)
			}

		case "auth-agent-req@openssh.com":
			accepted = true
			session.hasAgent = true
			session.agentUnixID = fmt.Sprintf("ux-%s%d", connInfo.connId, connInfo.SeqNumber())
			session.sshAuthSock = fmt.Sprintf(SSH_AUTH_SOCK_TEMP, session.agentUnixID)
			s.log.Debug().Msgf("SSH agent forwarding request accepted for user %s", session.username)
			session.env = append(session.env, fmt.Sprintf("SSH_AUTH_SOCK=%s",
				session.sshAuthSock))
			connInfo.AddChannelInfo(models.ChannelShortAf)

		default:
			s.log.Warn().Msgf("Unsupported session request type: %s for user %s", req.Type, session.username)
		}

		if req.WantReply {
			err := req.Reply(accepted, nil)
			if err != nil {
				s.log.Error().Msgf("Failed to reply to session request: %v", err)
			}
		}
	}

	if !sessionTypeSent {
		sessionType <- "none"
	}
}

// ** SSH Shell

// handleShellRequest handles a shell request for a user
func (s *Server) handleShellRequest(sshConn *ssh.ServerConn, connInfo *Connection, channel ssh.Channel) {
	session := connInfo.session

	var stopCtrlC chan struct{}
	if connInfo.session.hasPTY {
		stopCtrlC = make(chan struct{})
		go s.cancelOnCtrlC(channel, connInfo, stopCtrlC)
	}

	k8shelld, err := connInfo.Handshake(channel, &s.Config.Server.WriterOptions, s)
	if stopCtrlC != nil {
		close(stopCtrlC)
	}
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for user %s: %v", connInfo.user.Username, err)
		return
	}

	userToken, err := connInfo.GetUserToken()
	if err != nil {
		s.log.Error().Msgf("Failed to get user token for user %s: %v", connInfo.user.Username, err)
		return
	}

	if authzErr := s.checkSSHAuthz(connInfo.ctx, userToken,
		authz.NewSSHEvalRequest(authz.SSHActionShell, connInfo.workspaceName).
			WithOwner(connInfo.user.Username).
			WithAsUser(connInfo.userStr.User()).
			WithBlueprint(connInfo.userStr.Blueprint()).
			WithPTY(session.hasPTY),
	); authzErr != nil {
		s.log.Warn().Msgf("SSH shell denied for user %s: %v", connInfo.user.Username, authzErr)
		return
	}

	recordShell := s.Config.Server.Recording.RecordShell
	if ob, found, authzErr := s.checkSessionAuthz(connInfo.ctx, userToken,
		authz.NewSessionEvalRequest(authz.SessionActionStart, connInfo.workspaceName, authz.SessionTypeShell).
			WithSource(authz.SessionSourceSSHProxy).
			WithOwner(connInfo.user.Username).
			WithBlueprint(connInfo.userStr.Blueprint()),
	); authzErr != nil {
		s.log.Warn().Msgf("Session start denied for user %s: %v", connInfo.user.Username, authzErr)
		return
	} else if found {
		recordShell = ob.Shell
	}

	if session.hasAgent {
		if authzErr := s.checkSSHAuthz(connInfo.ctx, userToken,
			authz.NewSSHEvalRequest(authz.SSHActionAgentForward, connInfo.workspaceName).
				WithOwner(connInfo.user.Username),
		); authzErr != nil {
			s.log.Warn().Msgf("Agent forwarding denied for user %s: %v", connInfo.user.Username, authzErr)
			session.hasAgent = false
		}
	}

	if session.hasAgent {
		agentChannel, err := s.handleAgent(sshConn, connInfo)
		if err != nil {
			s.log.Error().Msgf("Failed to create agent channel: %v", err)
		} else {
			defer agentChannel.Close()
		}
	}

	if s.authzClient == nil && connInfo.userStr.User() == "root" && !connInfo.user.Sudo {
		s.log.Warn().Msgf("User %s requested root shell without sudo permissions, denying shell access",
			connInfo.user.Username)
		return
	}

	s.log.Debug().Msgf("Starting shell session for user %s, session ID: %s, requested user: %s",
		session.username, session.sessionId, session.username)

	rw := &workspace.ChannelAdapter{Channel: channel}
	if err := k8shelld.RunShell(connInfo.ctx, userToken, connInfo.userStr.User(), rw,
		session.sessionId, session.env, session.termWidth, session.termHeight,
		session.hasPTY, "", false, true, recordShell, connInfo.SetPtyName); err != nil {
		s.log.Error().Msgf("Shell session error: %v", err)
	} else {
		s.log.Debug().Msgf("Shell session %s completed for user %s", session.sessionId, session.username)
	}
}

func (s *Server) cancelOnCtrlC(channel ssh.Channel, connInfo *Connection, stopChan chan struct{}) {
	buffer := make([]byte, 1)
	for {
		select {
		case <-stopChan:
			return
		default:
			size, err := channel.ReadBufferSize()
			if err != nil {
				return
			}

			if size > 0 {
				n, err := channel.Read(buffer)
				if err != nil {
					return
				}

				if n > 0 && buffer[0] == 3 {
					s.log.Info().Msgf("Ctrl+C detected, canceling shell session")
					connInfo.cancel()
					return
				}
			} else {
				select {
				case <-stopChan:
					return
				case <-time.After(10 * time.Millisecond):
					// Continue checking
				}
			}
		}
	}
}

// ** SFTP

func (s *Server) handleSFTPSubsystem(_ *ssh.ServerConn, connInfo *Connection, channel ssh.Channel) {
	session := connInfo.session
	s.log.Info().Msgf("Handling sftp subsystem in channel for user %s, command: %s", session.username, session.command)

	k8shelld, err := connInfo.Handshake(nil, nil, s)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for sftp exec: %v", err)
		return
	}

	if session.signalChan != nil {
		s.log.Error().Msgf("Signal channel already exists for user %s, cannot start exec", session.username)
		return
	}

	session.signalChan = make(chan string, 10)
	defer func() {
		close(session.signalChan)
		session.signalChan = nil
	}()

	userToken, err := connInfo.GetUserToken()
	if err != nil {
		s.log.Error().Msgf("Failed to get user token for user %s: %v", connInfo.user.Username, err)
		return
	}

	if authzErr := s.checkSSHAuthz(connInfo.ctx, userToken,
		authz.NewSSHEvalRequest(authz.SSHActionSFTP, connInfo.workspaceName).
			WithOwner(connInfo.user.Username),
	); authzErr != nil {
		s.log.Warn().Msgf("SSH sftp denied for user %s: %v", connInfo.user.Username, authzErr)
		return
	}

	execID := fmt.Sprintf("sf-%s%d", connInfo.connId, connInfo.SeqNumber())
	s.log.Debug().Msgf("Starting sftp for user %s, exec ID: %s, command: %s",
		session.username, execID, s.Config.Server.SftpBinary)

	rw := &workspace.ChannelAdapter{Channel: channel}
	exitcode, err := k8shelld.RunExec(connInfo.ctx, userToken, connInfo.userStr.User(), rw, execID,
		s.Config.Server.SftpBinary, "", []string{}, session.signalChan, s.Config.Server.Recording.RecordExec)
	if err != nil {
		s.log.Error().Msgf("sftp exec failed for command '%s': %v", s.Config.Server.SftpBinary, err)
	}

	s.log.Debug().Msgf("sftp '%s' executed in the workspace, exit-code=%d", s.Config.Server.SftpBinary, exitcode)
	s.sendExitStatus(channel, exitcode)
}

// ** SSH Exec

// handleExecRequest handles an exec request for a user
func (s *Server) handleExecRequest(connInfo *Connection, channel ssh.Channel) {
	session := connInfo.session
	s.log.Info().Msgf("Handling exec in channel for user %s, command: %s", session.username, session.command)

	k8shelld, err := connInfo.Handshake(nil, nil, s)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for exec: %v", err)
		s.sendExitStatus(channel, 1)
		return
	}

	if session.signalChan != nil {
		s.log.Error().Msgf("Signal channel already exists for user %s, cannot start exec", session.username)
		return
	}

	session.signalChan = make(chan string, 10)
	defer func() {
		close(session.signalChan)
		session.signalChan = nil
	}()

	userToken, err := connInfo.GetUserToken()
	if err != nil {
		s.log.Error().Msgf("Failed to get user token for user %s: %v", connInfo.user.Username, err)
		return
	}

	if authzErr := s.checkSSHAuthz(connInfo.ctx, userToken,
		authz.NewSSHEvalRequest(authz.SSHActionExec, connInfo.workspaceName).
			WithOwner(connInfo.user.Username).
			WithCommand(session.command),
	); authzErr != nil {
		s.log.Warn().Msgf("SSH exec denied for user %s: %v", connInfo.user.Username, authzErr)
		s.sendExitStatus(channel, 1)
		return
	}

	recordExec := s.Config.Server.Recording.RecordExec
	if ob, found, authzErr := s.checkSessionAuthz(connInfo.ctx, userToken,
		authz.NewSessionEvalRequest(authz.SessionActionStart, connInfo.workspaceName, authz.SessionTypeExec).
			WithSource(authz.SessionSourceSSHProxy).
			WithOwner(connInfo.user.Username).
			WithBlueprint(connInfo.userStr.Blueprint()),
	); authzErr != nil {
		s.log.Warn().Msgf("Session start denied for user %s: %v", connInfo.user.Username, authzErr)
		s.sendExitStatus(channel, 1)
		return
	} else if found {
		recordExec = ob.Exec
	}

	execID := fmt.Sprintf("ex-%s%d", connInfo.connId, connInfo.SeqNumber())
	s.log.Debug().Msgf("Starting exec for user %s, exec ID: %s, command: %s",
		session.username, execID, session.command)

	rw := &workspace.ChannelAdapter{Channel: channel}
	exitcode, err := k8shelld.RunExec(connInfo.ctx, userToken, connInfo.userStr.User(), rw, execID, session.command,
		"/bin/sh", session.env, session.signalChan, recordExec)
	if err != nil {
		s.log.Error().Msgf("Exec failed for command '%s': %v", session.command, err)
	}

	s.log.Debug().Msgf("Command '%s' executed in the workspace, exit-code=%d", session.command, exitcode)
	s.sendExitStatus(channel, exitcode)
}

// sendExitStatus sends SSH exit status to the client
func (s *Server) sendExitStatus(channel ssh.Channel, exitcode int32) {
	if exitcode < 0 {
		s.log.Warn().Msgf("The command exit code is negative (%d). Setting it to 1", exitcode)
		exitcode = 1
	}

	exitStatus := make([]byte, 4)

	var code uint32
	if exitcode < 0 {
		code = 255
	} else {
		code = uint32(exitcode)
	}

	binary.BigEndian.PutUint32(exitStatus, code)

	if _, err := channel.SendRequest("exit-status", false, exitStatus); err != nil {
		s.log.Error().Msgf("Failed to send exit status: %v", err)
	}
}

// ** SSH Agent forwarding

// createAgentChannel creates a server-initiated agent forwarding channel and
// handles the communication between the SSH agent and the unix socket in the workspace
func (s *Server) handleAgent(sshConn *ssh.ServerConn, connInfo *Connection) (ssh.Channel, error) {
	s.log.Debug().Msgf("Creating agent channel for user %s", connInfo.userStr.Username())

	k8shelld := connInfo.k8shelld
	if k8shelld == nil {
		return nil, fmt.Errorf("k8shelld client does not exist for user %s", connInfo.userStr.Username())
	}

	channel, reqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open agent channel: %w", err)
	}
	go ssh.DiscardRequests(reqs)

	s.log.Debug().Msgf("Agent channel created for user %s", connInfo.userStr.Username())

	// handle communication with the SSH agent and the unix socket
	go func() {
		s.log.Debug().Msgf("Starting agent forwarding for user %s, unix socket id: %s",
			connInfo.userStr.Username(), connInfo.session.agentUnixID)

		userToken, err := connInfo.GetUserToken()
		if err != nil {
			s.log.Error().Msgf("Failed to get user token for user %s: %v", connInfo.user.Username, err)
			return
		}

		err = k8shelld.RunUnixSocket(connInfo.ctx, userToken, &workspace.ChannelAdapter{Channel: channel},
			connInfo.session.agentUnixID, connInfo.session.sshAuthSock, "UNIX_SOCKET_MODE_LISTEN")
		if err != nil {
			if statusErr, ok := status.FromError(err); ok && statusErr.Code() == codes.Canceled {
				s.log.Debug().Msgf("Agent forwarding canceled for user %s", connInfo.userStr.Username())
			} else {
				s.log.Error().Msgf("Agent forwarding deadline exceeded for user %s", connInfo.userStr.Username())
			}
		}
		s.log.Debug().Msgf("Agent channel closed for user %s", connInfo.userStr.Username())
	}()

	return channel, nil
}

// *** Helper functions

// Parse exec request payload
func (s *Server) parseExecRequest(payload []byte) (string, error) {
	if len(payload) < 4 {
		return "", fmt.Errorf("exec payload too short")
	}

	commandLen := binary.BigEndian.Uint32(payload[0:4])
	if len(payload) < int(4+commandLen) {
		return "", fmt.Errorf("invalid exec command length")
	}

	command := string(payload[4 : 4+commandLen])
	return command, nil
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
