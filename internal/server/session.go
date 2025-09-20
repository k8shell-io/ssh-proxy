package server

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/k8shell-io/common/models"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var SSH_AUTH_SOCK_TEMP = "/var/run/ssh-agent-%s.sock"
var SFTP_BINARY = "/usr/local/bin/sftp"

func (s *Server) handleSessionChannel(sshConn *ssh.ServerConn, connInfo *ConnectionInfo, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Error().Msgf("Failed to accept session channel for user %s: %v", connInfo.User.Username, err)
		return
	}
	defer channel.Close()

	session := &SessionInfo{
		Username:   connInfo.User.Username,
		Env:        []string{},
		SessionId:  fmt.Sprintf("sh-%s-%d", connInfo.proxyFullID, channel.LocalID()),
		TermWidth:  80,
		TermHeight: 24,
		HasPTY:     false,
	}
	connInfo.Session = session

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
		s.log.Warn().Msgf("No valid session request received for user %s", session.Username)
	}
}

func (s *Server) handleSessionRequests(requests <-chan *ssh.Request, connInfo *ConnectionInfo,
	channel ssh.Channel, sessionType chan<- string) {
	sessionTypeSent := false
	session := connInfo.Session

	for req := range requests {
		s.log.Debug().Msgf("Received session request: type=%s, want_reply=%t, payload_len=%d",
			req.Type, req.WantReply, len(req.Payload))

		accepted := false
		switch req.Type {
		case "subsystem":
			if len(req.Payload) < 4 {
				req.Reply(false, nil)
				continue
			}

			nameLen := uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 |
				uint32(req.Payload[2])<<8 | uint32(req.Payload[3])
			if len(req.Payload) < int(4+nameLen) {
				req.Reply(false, nil)
				continue
			}

			subsystemName := string(req.Payload[4 : 4+nameLen])
			s.log.Debug().Msgf("Subsystem request: %s", subsystemName)

			if subsystemName == "sftp" {
				req.Reply(true, nil)
				connInfo.AddChannelInfo(models.ChannelShortSf)
				sessionType <- "sftp"
				sessionTypeSent = true
			} else {
				s.log.Warn().Msgf("Unsupported subsystem: %s", subsystemName)
				req.Reply(false, nil)
			}
		case "pty-req":
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
			connInfo.AddChannelInfo(models.ChannelShortPt)
			s.log.Debug().Msgf("PTY request accepted for user %s", session.Username)

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
			accepted = true
			s.log.Debug().Msgf("Shell request accepted for user %s", session.Username)
			sessionType <- "shell"
			sessionTypeSent = true
			connInfo.AddChannelInfo(models.ChannelShortSh)

		case "exec":
			command, err := s.parseExecRequest(req.Payload)
			if err != nil {
				s.log.Error().Msgf("Failed to parse exec request: %v", err)
			} else {
				accepted = true
				session.Command = command
				s.log.Debug().Msgf("Exec request accepted for user %s: %s", session.Username, command)
				sessionType <- "exec"
				sessionTypeSent = true
				connInfo.AddChannelInfo(models.ChannelShortEx)
			}

		case "signal":
			if len(req.Payload) < 4 {
				req.Reply(false, nil)
				continue
			}

			nameLen := binary.BigEndian.Uint32(req.Payload[0:4])
			if len(req.Payload) < int(4+nameLen) {
				req.Reply(false, nil)
				continue
			}

			signalName := string(req.Payload[4 : 4+nameLen])
			s.log.Debug().Msgf("Signal request: %s", signalName)

			if session.SignalChan != nil {
				select {
				case session.SignalChan <- signalName:
					accepted = true
					s.log.Debug().Msgf("Signal %s sent to active exec process for user %s", signalName, session.Username)
				default:
					s.log.Warn().Msgf("Signal channel full, couldn't send signal %s for user %s", signalName, session.Username)
					accepted = false
				}
			} else {
				s.log.Warn().Msgf("No active exec session to send signal %s for user %s", signalName, session.Username)
				accepted = false
			}

		case "window-change":
			k8shelld := connInfo.k8shelld
			if k8shelld != nil {
				if len(req.Payload) >= 8 {
					accepted = true
					width := binary.BigEndian.Uint32(req.Payload[0:4])
					height := binary.BigEndian.Uint32(req.Payload[4:8])

					s.log.Debug().Msgf("Window change: %dx%d for user %s", width, height, session.Username)
					session.TermWidth = width
					session.TermHeight = height

					if err := k8shelld.ResizeTerminal(connInfo.Ctx, session.SessionId, width, height); err != nil {
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
			session.AgentUnixID = fmt.Sprintf("ux-%s-%d", connInfo.proxyFullID, channel.LocalID())
			session.SSHAuthSock = fmt.Sprintf(SSH_AUTH_SOCK_TEMP, session.AgentUnixID)
			s.log.Debug().Msgf("SSH agent forwarding request accepted for user %s", session.Username)
			session.Env = append(session.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s",
				session.SSHAuthSock))
			connInfo.AddChannelInfo(models.ChannelShortAf)

		default:
			s.log.Warn().Msgf("Unsupported session request type: %s for user %s", req.Type, session.Username)
		}

		if req.WantReply {
			req.Reply(accepted, nil)
		}
	}

	if !sessionTypeSent {
		sessionType <- "none"
	}
}

// ** SSH Shell

// handleShellRequest handles a shell request for a user
func (s *Server) handleShellRequest(sshConn *ssh.ServerConn, connInfo *ConnectionInfo, channel ssh.Channel) {
	session := connInfo.Session

	stopChan := make(chan struct{})

	go func() {
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
						s.log.Info().Msgf("Ctrl+C detected for user %s, canceling shell session", session.Username)
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
	}()

	k8shelld, err := connInfo.CreateK8shelldClient(connInfo.Ctx, channel, s.Config.Server.ShowProvisionInfo,
		s.provisioner, session.Env)
	close(stopChan)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for user %s: %v", connInfo.User.Username, err)
		return
	}

	if session.HasAgent {
		agentChannel, err := s.handleAgent(sshConn, connInfo)
		if err != nil {
			s.log.Error().Msgf("Failed to create agent channel: %v", err)
		} else {
			defer agentChannel.Close()
		}
	}

	s.log.Debug().Msgf("Starting shell session for user %s, session ID: %s", session.Username, session.SessionId)

	if err := k8shelld.StartShell(connInfo.Ctx, channel, session.SessionId,
		session.Env, session.TermWidth, session.TermHeight, session.HasPTY, connInfo.counters); err != nil {
		s.log.Error().Msgf("Shell session error: %v", err)
	} else {
		s.log.Debug().Msgf("Shell session %s completed for user %s", session.SessionId, session.Username)
	}
}

// ** SFTP

func (s *Server) handleSFTPSubsystem(_ *ssh.ServerConn, connInfo *ConnectionInfo, channel ssh.Channel) {
	session := connInfo.Session
	s.log.Info().Msgf("Handling sftp subsystem in channel for user %s, command: %s", session.Username, session.Command)

	k8shelld, err := connInfo.CreateK8shelldClient(connInfo.Ctx, nil, false, s.provisioner, session.Env)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for sftp exec: %v", err)
		return
	}

	if session.SignalChan != nil {
		s.log.Error().Msgf("Signal channel already exists for user %s, cannot start exec", session.Username)
		return
	}

	session.SignalChan = make(chan string, 10)
	defer func() {
		close(session.SignalChan)
		session.SignalChan = nil
	}()

	execID := fmt.Sprintf("sf-%s-%d-%d", connInfo.proxyFullID, channel.LocalID(), connInfo.ExecSeqNumber())
	s.log.Debug().Msgf("Starting sftp for user %s, exec ID: %s, command: %s",
		session.Username, execID, SFTP_BINARY)

	_, err = k8shelld.StartExec(connInfo.Ctx, channel, execID, SFTP_BINARY, "", []string{}, session.SignalChan)
	if err != nil {
		s.log.Error().Msgf("Sftp exec failed for command '%s': %v", SFTP_BINARY, err)
	} else {
		s.log.Debug().Msgf("Sftp exec completed for user %s, exec ID: %s", session.Username, execID)
	}
}

// ** SSH Exec

// handleExecRequest handles an exec request for a user
func (s *Server) handleExecRequest(connInfo *ConnectionInfo, channel ssh.Channel) {
	session := connInfo.Session
	s.log.Info().Msgf("Handling exec in channel for user %s, command: %s", session.Username, session.Command)

	k8shelld, err := connInfo.CreateK8shelldClient(connInfo.Ctx, nil, false, s.provisioner, session.Env)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for exec: %v", err)
		s.sendExitStatus(channel, 1)
		return
	}

	if session.SignalChan != nil {
		s.log.Error().Msgf("Signal channel already exists for user %s, cannot start exec", session.Username)
		return
	}

	session.SignalChan = make(chan string, 10)
	defer func() {
		close(session.SignalChan)
		session.SignalChan = nil
	}()

	execID := fmt.Sprintf("ex-%s-%d-%d", connInfo.proxyFullID, channel.LocalID(), connInfo.ExecSeqNumber())
	s.log.Debug().Msgf("Starting exec for user %s, exec ID: %s, command: %s",
		session.Username, execID, session.Command)

	exitCode, err := k8shelld.StartExec(connInfo.Ctx, channel, execID, session.Command, "/bin/sh",
		session.Env, session.SignalChan)
	if err != nil {
		s.log.Error().Msgf("Exec failed for command '%s': %v", session.Command, err)
	}

	if exitCode < 0 {
		s.log.Warn().Msgf("The command exit code is -1 which is incorrect. Setting it to 1")
		exitCode = 1
	}

	if exitCode > 0 {
		s.log.Warn().Msgf("Command error '%s': exit code: %d", session.Command, exitCode)
	}

	s.log.Debug().Msgf("Command '%s' executed in the workspace, exit-code=%d", session.Command, exitCode)
	s.sendExitStatus(channel, exitCode)
}

// sendExitStatus sends SSH exit status to the client
func (s *Server) sendExitStatus(channel ssh.Channel, exitCode int32) {
	exitStatus := make([]byte, 4)
	binary.BigEndian.PutUint32(exitStatus, uint32(exitCode))
	channel.SendRequest("exit-status", false, exitStatus)
}

// ** SSH Agent forwarding

// createAgentChannel creates a server-initiated agent forwarding channel and
// handles the communication between the SSH agent and the unix socket in the workspace
func (s *Server) handleAgent(sshConn *ssh.ServerConn, connInfo *ConnectionInfo) (ssh.Channel, error) {
	s.log.Debug().Msgf("Creating agent channel for user %s", connInfo.UserStr.Username)

	k8shelld := connInfo.k8shelld
	if k8shelld == nil {
		return nil, fmt.Errorf("k8shelld client does not exist for user %s", connInfo.UserStr.Username)
	}

	channel, reqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open agent channel: %w", err)
	}
	go ssh.DiscardRequests(reqs)

	s.log.Debug().Msgf("Agent channel created for user %s", connInfo.UserStr.Username)

	// handle communication with the SSH agent and the unix socket
	go func() {
		s.log.Debug().Msgf("Starting agent forwarding for user %s, unix socket id: %s", connInfo.UserStr.Username,
			connInfo.Session.AgentUnixID)
		err := k8shelld.StartUnixSocket(connInfo.Ctx, channel, connInfo.Session.AgentUnixID, connInfo.Session.SSHAuthSock)
		if err != nil {
			if statusErr, ok := status.FromError(err); ok && statusErr.Code() == codes.Canceled {
				s.log.Debug().Msgf("Agent forwarding canceled for user %s", connInfo.UserStr.Username)
			} else {
				s.log.Error().Msgf("Agent forwarding deadline exceeded for user %s", connInfo.UserStr.Username)
			}
		}
		s.log.Debug().Msgf("Agent channel closed for user %s", connInfo.UserStr.Username)
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
