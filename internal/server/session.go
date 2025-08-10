package server

import (
	"encoding/binary"
	"fmt"
	"slices"

	identity "github.com/k8shell-io/identity/pkg/models"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	provisionerModels "github.com/k8shell-io/provisioner/pkg/models"
	"github.com/k8shell-io/ssh-proxy/internal/k8shelld"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var SSH_AUTH_SOCK = "/var/run/ssh-agent-12345.sock"

func (s *Server) handleSessionChannel(conn *ssh.ServerConn, auth *Auth, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Error().Msgf("Failed to accept session channel for user %s: %v", auth.User.Username, err)
		return
	}
	defer channel.Close()

	session := &SessionInfo{
		Auth:       auth,
		Username:   auth.User.Username,
		Env:        []string{},
		SessionId:  "sh-99999-0",
		ShellReady: make(chan struct{}),
		TermWidth:  80,
		TermHeight: 24,
	}

	go s.handleSessionRequests(requests, session, channel)

	status, err := s.ensureWorkspace(auth, channel)
	if err != nil {
		s.log.Error().Msgf("Failed to ensure workspace for user %s: %v", auth.User.Username, err)
		return
	}
	channel.Write([]byte(fmt.Sprintf("Connecting to the workspace at %s...\r\n", status.Host)))

	session.k8shelld, err = k8shelld.NewClient(status.Host, status.Port, status.AccessKey, status.TLSCert)
	if err != nil {
		s.log.Error().Msgf("Failed to create k8shelld client for user %s: %v", session.Username, err)
		return
	}
	defer session.k8shelld.Close()

	version, err := session.k8shelld.GetVersion(s.ctx)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld version for user %s: %v", session.Username, err)
		return
	}
	channel.Write([]byte(fmt.Sprintf("Connected to k8shelld (version: %s-%s)\r\n",
		version.Version, version.Commit)))

	<-session.ShellReady

	if session.HasAgent {
		err := s.handleAgent(conn, session)
		if err != nil {
			s.log.Error().Msgf("Failed to create agent channel: %v", err)
		}
	}

	if err := session.k8shelld.StartShell(s.ctx, channel, session.SessionId,
		session.Env, session.TermWidth, session.TermHeight); err != nil {
		s.log.Error().Msgf("Shell session error: %v", err)
	}
}

func (s *Server) handleSessionRequests(requests <-chan *ssh.Request, session *SessionInfo, _ ssh.Channel) {
	for req := range requests {
		s.log.Debug().Msgf("Received session request: type=%s, want_reply=%t, payload_len=%d",
			req.Type, req.WantReply, len(req.Payload))

		accepted := false

		switch req.Type {
		case "pty-req":
			if session.Auth.User.Channels == nil || slices.Contains(session.Auth.User.Channels, identity.ChannelPty) {
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
			if session.Auth.User.Channels == nil || slices.Contains(session.Auth.User.Channels, identity.ChannelShell) {
				accepted = true
				s.log.Debug().Msgf("Shell request accepted for user %s", session.Username)
			}
			close(session.ShellReady)

		case "window-change":
			accepted = true
			if session.k8shelld != nil {
				if len(req.Payload) >= 8 {
					width := binary.BigEndian.Uint32(req.Payload[0:4])
					height := binary.BigEndian.Uint32(req.Payload[4:8])

					s.log.Debug().Msgf("Window change: %dx%d for user %s", width, height, session.Username)
					session.TermWidth = width
					session.TermHeight = height

					if err := session.k8shelld.ResizeTerminal(s.ctx, session.SessionId, width, height); err != nil {
						s.log.Error().Msgf("Failed to resize terminal: %v", err)
					}
				}
			} else {
				s.log.Warn().Msgf("Received window-change request for user %s, but k8shelld is not initialized",
					session.Username)
			}

		case "auth-agent-req@openssh.com":
			accepted = true
			session.HasAgent = true
			s.log.Debug().Msgf("SSH agent forwarding request accepted for user %s", session.Username)
			session.Env = append(session.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", SSH_AUTH_SOCK))

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

func (s *Server) ensureWorkspace(auth *Auth, channel ssh.Channel) (*provisionerModels.WorkspaceStatus, error) {
	workspaces, err := s.provisioner.GetWorkspaces(s.ctx, auth.User.Username, auth.BpName)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", auth.User.Username, err)
	}

	if len(workspaces) > 0 {
		status, err := s.provisioner.GetWorkspaceStatus(s.ctx, workspaces[0].Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get workspace status for user %s: %w", auth.User.Username, err)
		}
		if status.Status == "Running" {
			return status, nil
		}
	}

	name, err := s.provisionWorkspace(channel, auth, true)
	if err != nil {
		return nil, fmt.Errorf("failed to provision workspace for user %s: %w", auth.User.Username, err)
	}

	status, err := s.provisioner.GetWorkspaceStatus(s.ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", auth.User.Username, err)
	}
	if status.Status == "Running" {
		return status, nil
	}

	return nil, fmt.Errorf("failed to ensure workspace for user %s: workspace status is %q",
		auth.User.Username, status.Status)
}

func (s *Server) provisionWorkspace(channel ssh.Channel, auth *Auth, sendEvents bool) (string, error) {
	events := make(chan provisionerModels.StreamEvent, 100)
	channel.Write([]byte("Provisioning workspace...\r\n"))

	var name string
	var err error

	go func() {
		err = s.provisioner.ProvisionWorkspaceStream(s.ctx, &provisioner.ProvisionOptions{
			Username:  auth.User.Username,
			Blueprint: auth.BpName,
			Timeout:   30,
			Stream:    true,
		}, events)
		if err != nil {
			s.log.Error().Msgf("Provisioning error: %v", err)
		}
	}()

	provisioningDone := make(chan bool, 1)

	go func() {
		defer func() { provisioningDone <- true }()

		for event := range events {
			s.log.Debug().Msgf("Event: %+v", event)
			if sendEvents {
				channel.Write([]byte(fmt.Sprintf("%s\r\n", event.String())))
			}

			if event.Status == "Running" {
				name = event.ObjectName
			}

			if event.Status == "Error" {
				err = fmt.Errorf("provisioning error: %s", event.Message)
			}
		}
	}()

	<-provisioningDone
	return name, err
}

// createAgentChannel creates a server-initiated agent forwarding channel and
// handles the communication between the SSH agent and the unix socket in the workspace
func (s *Server) handleAgent(sshConn *ssh.ServerConn, session *SessionInfo) error {
	s.log.Debug().Msgf("Creating agent channel for user %s", session.Username)
	channel, reqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return fmt.Errorf("failed to open agent channel: %w", err)
	}

	go ssh.DiscardRequests(reqs)

	s.log.Debug().Msgf("Agent channel created for user %s", session.Username)

	// handle communication with the SSH agent and the unix socket
	go func() {
		defer channel.Close()

		err := session.k8shelld.StartUnixSocketWithConnection(s.ctx, channel, session.SessionId, SSH_AUTH_SOCK)
		if err != nil {
			if statusErr, ok := status.FromError(err); ok && statusErr.Code() == codes.Canceled {
				s.log.Debug().Msgf("Agent forwarding canceled for user %s", session.Username)
			} else {
				s.log.Error().Msgf("Agent forwarding deadline exceeded for user %s", session.Username)
			}
		}
	}()

	return nil
}
