package server

import (
	"github.com/k8shell-io/common/models"
	"golang.org/x/crypto/ssh"
)

// handleChannels handles SSH channel requests.
func (s *Server) handleChannels(sshConn *ssh.ServerConn, connInfo *ConnectionInfo, channels <-chan ssh.NewChannel) {
	for newChannel := range channels {
		s.log.Debug().Msgf("Received channel request: type=%s", newChannel.ChannelType())
		switch newChannel.ChannelType() {
		case "session":
			go s.handleSessionChannel(sshConn, connInfo, newChannel)
		case "direct-tcpip":
			connInfo.AddChannelInfo(models.ChannelShortPf)
			go s.handleDirectTCPIPChannel(sshConn, connInfo, newChannel)
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

		// Reject unknown global requests
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}
