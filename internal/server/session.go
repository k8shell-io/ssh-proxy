package server

import (
	"fmt"
	"slices"

	identity "github.com/k8shell-io/identity/pkg/models"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	provisionerModels "github.com/k8shell-io/provisioner/pkg/models"
	"github.com/k8shell-io/ssh-proxy/internal/k8shelld"
	"golang.org/x/crypto/ssh"
)

func (s *Server) handleSessionChannel(_ *ssh.ServerConn, state *State, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Error().Msgf("Failed to accept session channel for user %s: %v", state.User.Username, err)
		return
	}
	defer channel.Close()

	session := &SessionInfo{
		State:      state,
		Username:   state.User.Username,
		Env:        []string{},
		SessionId:  "sh-99999-0",
		ShellReady: make(chan struct{}),
		TermWidth:  80,
		TermHeight: 24,
	}

	go s.handleSessionRequests(requests, session, channel)

	status, err := s.ensureWorkspace(state, channel)
	if err != nil {
		s.log.Error().Msgf("Failed to ensure workspace for user %s: %v", state.User.Username, err)
		return
	}
	channel.Write([]byte(fmt.Sprintf("Connecting to the workspace at %s...\r\n", status.Host)))

	session.k8shelld, err = k8shelld.NewClient(status.Host, 2822, status.AccessKey, status.TLSCert)
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
	channel.Write([]byte(fmt.Sprintf("Connected to k8shelld (version: %s, commit: %s)\r\n",
		version.Version, version.Commit)))

	// wait for shell request to be accepted
	<-session.ShellReady

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
			if session.State.User.Channels == nil || slices.Contains(session.State.User.Channels, identity.ChannelPty) {
				if len(req.Payload) >= 8 {
					termLen := uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 |
						uint32(req.Payload[2])<<8 | uint32(req.Payload[3])

					if len(req.Payload) >= int(4+termLen) {
						termType := string(req.Payload[4 : 4+termLen])

						termEnv := fmt.Sprintf("TERM=%s", termType)
						session.Env = append(session.Env, termEnv)
						s.log.Debug().Msgf("Terminal type: %s for user %s", termType, session.Username)

						offset := 4 + int(termLen)
						if len(req.Payload) >= offset+16 {
							session.TermWidth = uint32(req.Payload[offset])<<24 |
								uint32(req.Payload[offset+1])<<16 |
								uint32(req.Payload[offset+2])<<8 |
								uint32(req.Payload[offset+3])
							session.TermHeight = uint32(req.Payload[offset+4])<<24 |
								uint32(req.Payload[offset+5])<<16 |
								uint32(req.Payload[offset+6])<<8 |
								uint32(req.Payload[offset+7])

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
				nameLen := uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 |
					uint32(req.Payload[2])<<8 | uint32(req.Payload[3])

				if len(req.Payload) >= int(4+nameLen+4) {
					name := string(req.Payload[4 : 4+nameLen])
					valueOffset := 4 + nameLen
					valueLen := uint32(req.Payload[valueOffset])<<24 | uint32(req.Payload[valueOffset+1])<<16 |
						uint32(req.Payload[valueOffset+2])<<8 | uint32(req.Payload[valueOffset+3])

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
			if session.State.User.Channels == nil || slices.Contains(session.State.User.Channels, identity.ChannelShell) {
				accepted = true
				s.log.Debug().Msgf("Shell request accepted for user %s", session.Username)
			}
			close(session.ShellReady)

		case "window-change":
			accepted = true
			if session.k8shelld != nil {
				if len(req.Payload) >= 8 {
					width := uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 |
						uint32(req.Payload[2])<<8 | uint32(req.Payload[3])
					height := uint32(req.Payload[4])<<24 | uint32(req.Payload[5])<<16 |
						uint32(req.Payload[6])<<8 | uint32(req.Payload[7])

					session.TermWidth = width
					session.TermHeight = height

					s.log.Debug().Msgf("Window change: %dx%d for user %s", width, height, session.Username)

					if err := session.k8shelld.ResizeTerminal(s.ctx, session.SessionId, width, height); err != nil {
						s.log.Error().Msgf("Failed to resize terminal: %v", err)
					}
				}
			} else {
				s.log.Warn().Msgf("Received window-change request for user %s, but k8shelld is not initialized",
					session.Username)
			}

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

func (s *Server) ensureWorkspace(state *State, channel ssh.Channel) (*provisionerModels.WorkspaceStatus, error) {
	workspaces, err := s.provisioner.GetWorkspaces(s.ctx, state.User.Username, "dev")
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", state.User.Username, err)
	}

	if len(workspaces) > 0 {
		status, err := s.provisioner.GetWorkspaceStatus(s.ctx, workspaces[0].Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get workspace status for user %s: %w", state.User.Username, err)
		}
		if status.Status == "Running" {
			return status, nil
		}
	}

	name, err := s.provisionWorkspace(channel, state, true)
	if err != nil {
		return nil, fmt.Errorf("failed to provision workspace for user %s: %w", state.User.Username, err)
	}

	status, err := s.provisioner.GetWorkspaceStatus(s.ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", state.User.Username, err)
	}
	if status.Status == "Running" {
		return status, nil
	}

	return nil, fmt.Errorf("failed to ensure workspace for user %s: workspace status is %q",
		state.User.Username, status.Status)
}

func (s *Server) provisionWorkspace(channel ssh.Channel, state *State, sendEvents bool) (string, error) {
	events := make(chan provisionerModels.StreamEvent, 100)
	channel.Write([]byte("Provisioning workspace...\r\n"))

	var name string
	var err error

	go func() {
		err = s.provisioner.ProvisionWorkspaceStream(s.ctx, &provisioner.ProvisionOptions{
			Username:  state.User.Username,
			Blueprint: "dev",
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
