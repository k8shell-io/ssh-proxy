package server

import (
	"fmt"
	"slices"

	identity "github.com/k8shell-io/identity/pkg/models"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
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

	events := make(chan provisioner.StreamEvent, 100)
	channel.Write([]byte("Provisioning workspace...\r\n"))

	go func() {
		err := s.provisioner.ProvisionWorkspaceStream(s.ctx, &provisioner.ProvisionOptions{
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
			s.log.Debug().Msgf("Received event: %+v", event)
			channel.Write([]byte(fmt.Sprintf("%s\r\n", event.String())))

			if event.Status == "Error" {
				return
			}
		}
	}()

	<-provisioningDone
	channel.Write([]byte("Workspace provisioned successfully!\r\n"))
}

func (s *Server) handleSessionRequests(requests <-chan *ssh.Request, state *State) {
	for req := range requests {
		s.log.Debug().Msgf("Received session request: type=%s, want_reply=%t", req.Type, req.WantReply)

		accepted := false

		switch req.Type {
		case "pty-req":
			if state.User.Channels != nil || !slices.Contains(state.User.Channels, identity.ChannelPty) {
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
