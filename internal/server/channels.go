package server

import (
	"github.com/k8shell-io/common/models"
	"golang.org/x/crypto/ssh"
)

// handleChannels handles SSH channel requests.
func (s *Server) handleChannels(sshConn *ssh.ServerConn, connInfo *Connection, channels <-chan ssh.NewChannel) {
	for {
		select {
		case <-s.ctx.Done():
			s.log.Info().Msg("Channel handler stopping due to context cancellation")
			return
		case channel := <-channels:
			if channel == nil {
				return
			}
			s.log.Debug().Msgf("Received channel request: type=%s", channel.ChannelType())
			switch channel.ChannelType() {
			case "session":
				go s.handleSessionChannel(sshConn, connInfo, channel)
			case "direct-tcpip":
				connInfo.AddChannelInfo(models.ChannelShortPf)
				go s.handleDirectTCPIPChannel(sshConn, connInfo, channel)
			default:
				s.log.Warn().Msgf("Unsupported channel type: %s", channel.ChannelType())
				channel.Reject(ssh.UnknownChannelType, "channel type not supported")
			}
		}
	}
}

// handleGlobalRequests processes SSH global requests
func (s *Server) handleGlobalRequests(requests <-chan *ssh.Request) {
	for {
		select {
		case <-s.ctx.Done():
			s.log.Info().Msg("Global request handler stopping due to context cancellation")
			return
		case req := <-requests:
			if req == nil {
				return
			}
			s.log.Debug().Msgf("Received global request: type=%s, want_reply=%t", req.Type, req.WantReply)

			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}
