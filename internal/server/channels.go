package server

import (
	"errors"
	"fmt"

	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	provisionerModels "github.com/k8shell-io/provisioner/pkg/models"
	"github.com/k8shell-io/ssh-proxy/internal/k8shelld"
	"golang.org/x/crypto/ssh"
)

// handleChannels handles SSH channel requests.
func (s *Server) handleChannels(sshConn *ssh.ServerConn, channels <-chan ssh.NewChannel) {
	connInfo := GetConnInfo(sshConn)
	if connInfo.User == nil {
		s.log.Error().Msgf("There is no user identity associated with username %s. Cannot handle channels.",
			sshConn.User())
		return
	}
	defer connInfo.Close()

	for newChannel := range channels {
		s.log.Debug().Msgf("Received channel request: type=%s", newChannel.ChannelType())

		switch newChannel.ChannelType() {
		case "session":
			go s.handleSessionChannel(sshConn, connInfo, newChannel)
		case "direct-tcpip":
			// Handle direct TCP/IP channel
		default:
			s.log.Warn().Msgf("Unsupported channel type: %s", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "channel type not supported")
		}
	}
}

// handleGlobalRequests processes SSH global requests
func (s *Server) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		s.log.Debug().Msgf("Received global request: type=%s, want_reply=%t", req.Type, req.WantReply)

		// Reject all global requests for now
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

func (s *Server) getK8shelld(connInfo *ConnectionInfo, channel ssh.Channel) (*k8shelld.Client, error) {
	connInfo.mu.RLock()
	defer connInfo.mu.RUnlock()

	if connInfo.k8shelld != nil {
		return connInfo.k8shelld, nil
	}

	status, err := s.ensureWorkspace(connInfo, channel)
	if err != nil {
		s.log.Error().Msgf("Failed to ensure workspace for user %s: %v", connInfo.User.Username, err)
		return nil, err
	}
	if channel != nil {
		channel.Write([]byte(fmt.Sprintf("Connecting to the workspace at %s...\r\n", status.Host)))
	}

	connInfo.k8shelld, err = k8shelld.NewClient(status.Host, status.Port, status.AccessKey, status.TLSCert)
	if err != nil {
		s.log.Error().Msgf("Failed to create k8shelld client for user %s: %v", connInfo.User.Username, err)
		return nil, err
	}

	version, err := connInfo.k8shelld.GetVersion(s.ctx)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld version for user %s: %v", connInfo.User.Username, err)
		return nil, err
	}
	if channel != nil {
		channel.Write([]byte(fmt.Sprintf("Connected to k8shelld (version: %s-%s)\r\n",
			version.Version, version.Commit)))
	}

	return connInfo.k8shelld, nil
}

func (s *Server) ensureWorkspace(auth *ConnectionInfo, channel ssh.Channel) (*provisionerModels.WorkspaceStatus, error) {
	workspaces, err := s.provisioner.GetWorkspaces(s.ctx, auth.User.Username, auth.BlueprintName)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", auth.User.Username, err)
	}

	if len(workspaces) > 0 {
		status, err := s.provisioner.GetWorkspaceStatus(s.ctx, workspaces[0].Name)
		if err != nil {
			if errors.Is(err, provisionerModels.ErrWorkspaceNotFound) {
				s.log.Warn().Msgf("Workspace %s not found for user %s, provisioning new workspace", workspaces[0].Name,
					auth.User.Username)
			} else {
				return nil, fmt.Errorf("failed to get workspace status for user %s: %w", auth.User.Username, err)
			}
		} else {
			if status.Status == "Running" {
				return status, nil
			}
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

func (s *Server) provisionWorkspace(channel ssh.Channel, auth *ConnectionInfo, sendEvents bool) (string, error) {
	events := make(chan provisionerModels.StreamEvent, 100)
	if channel != nil {
		channel.Write([]byte("Provisioning workspace...\r\n"))
	}
	var name string
	var err error

	go func() {
		err = s.provisioner.ProvisionWorkspaceStream(s.ctx, &provisioner.ProvisionOptions{
			Username:  auth.User.Username,
			Blueprint: auth.BlueprintName,
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
			if sendEvents && channel != nil {
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
