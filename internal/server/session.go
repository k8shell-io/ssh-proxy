package server

import (
	"fmt"
	"slices"

	identity "github.com/k8shell-io/identity/pkg/models"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	provisionerModels "github.com/k8shell-io/provisioner/pkg/models"
	"golang.org/x/crypto/ssh"
)

func (s *Server) handleSessionChannel(_ *ssh.ServerConn, state *State, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Error().Msgf("Failed to accept session channel for user %s: %v", state.User.Username, err)
		return
	}
	defer channel.Close()

	state.Session = &SessionInfo{
		Username:    state.User.Username,
		Environment: make(map[string]string),
	}

	go s.handleSessionRequests(requests, state)

	address, err := s.getWorkspaceAddress(state, channel)
	if err != nil {
		s.log.Error().Msgf("Failed to get workspace address for user %s: %v", state.User.Username, err)
		return
	}
	channel.Write([]byte(fmt.Sprintf("Connecting to workspace at %s...\r\n", address)))
}

func (s *Server) handleSessionRequests(requests <-chan *ssh.Request, state *State) {
	for req := range requests {
		s.log.Debug().Msgf("Received session request: type=%s, want_reply=%t", req.Type, req.WantReply)

		accepted := false

		switch req.Type {
		case "pty-req":
			if state.User.Channels != nil || !slices.Contains(state.User.Channels, identity.ChannelPty) {
				state.Session.HasPTY = true
				accepted = true
			}

		// case "env":
		// 	accepted = s.handleEnvRequest(req.Payload, state.Session)

		case "shell":
			if state.User.Channels != nil || !slices.Contains(state.User.Channels, identity.ChannelShell) {
				accepted = true
			}
			s.log.Debug().Msgf("Shell request accepted for user %s, payload: %s", state.User.Username, req.Payload)

		// case "exec":
		// 	accepted = s.handleExecRequest(req.Payload, sessionInfo, channel)

		// case "window-change":
		// 	accepted = s.handleWindowChangeRequest(req.Payload, sessionInfo)

		default:
			s.log.Warn().Msgf("Unsupported session request type: %s", req.Type)
		}

		if req.WantReply {
			req.Reply(accepted, nil)
		}
	}
}

func (s *Server) getWorkspaceAddress(state *State, channel ssh.Channel) (string, error) {
	workspaces, err := s.provisioner.GetWorkspaces(s.ctx, state.User.Username, "dev")
	if err != nil {
		return "", fmt.Errorf("failed to get workspace status for user %s: %w", state.User.Username, err)
	}

	var address string
	if len(workspaces) > 0 {
		status, err := s.provisioner.GetWorkspaceStatus(s.ctx, workspaces[0].Name)
		if err != nil {
			return "", fmt.Errorf("failed to get workspace status for user %s: %w", state.User.Username, err)
		}
		if status.Status == "Running" {
			return status.Host, nil
		}
	}

	address, err = s.provisionWorkspace(channel, state, true)
	if err != nil {
		return "", fmt.Errorf("failed to provision workspace for user %s: %w", state.User.Username, err)
	}
	if address == "" {
		return "", fmt.Errorf("failed to provision workspace for user %s: no workspace address available",
			state.User.Username)
	}
	return address, nil
}

func (s *Server) provisionWorkspace(channel ssh.Channel, state *State, sendEvents bool) (string, error) {
	events := make(chan provisionerModels.StreamEvent, 100)
	channel.Write([]byte("Provisioning workspace...\r\n"))

	var address string
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
				address = event.Host
			}

			if event.Status == "Error" {
				err = fmt.Errorf("provisioning error: %s", event.Message)
			}
		}
	}()

	<-provisioningDone
	return address, err
}
