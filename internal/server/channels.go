package server

import (
	"golang.org/x/crypto/ssh"
)

// handleChannels handles SSH channel requests.
func (s *Server) handleChannels(sshConn *ssh.ServerConn, channels <-chan ssh.NewChannel) {
	for newChannel := range channels {
		s.log.Debug().Msgf("Received channel request: type=%s", newChannel.ChannelType())

		auth := GetAuth(sshConn)
		if auth.User == nil {
			s.log.Error().Msgf("User not found for connection %s, rejecting channel request", sshConn.User())
			newChannel.Reject(ssh.UnknownChannelType, "user not found")
			continue
		}

		switch newChannel.ChannelType() {
		case "session":
			go s.handleSessionChannel(sshConn, auth, newChannel)
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
