package server

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// handleDirectTCPIPChannel handles a new direct TCP/IP channel request
func (s *Server) handleDirectTCPIPChannel(_ *ssh.ServerConn, connInfo *Connection, newChannel ssh.NewChannel) {
	if !connInfo.IncrementDirectTCPIPCount(s.Config.Server.MaxDirectTCPIPConnections) {
		s.log.Warn().Msgf("User %s exceeded max direct-tcpip connections (limit: %d)",
			connInfo.user.Username, s.Config.Server.MaxDirectTCPIPConnections)
		newChannel.Reject(ssh.ResourceShortage,
			fmt.Sprintf("maximum direct-tcpip connections exceeded (%d)", s.Config.Server.MaxDirectTCPIPConnections))
		return
	}

	tcpipInfo, err := parseDirectTCPIPPayload(newChannel.ExtraData())
	if err != nil {
		s.log.Error().Msgf("Failed to parse direct-tcpip payload: %v", err)
		newChannel.Reject(ssh.UnknownChannelType, "invalid payload")
		connInfo.DecrementDirectTCPIPCount()
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Error().Msgf("Failed to accept direct-tcpip channel: %v", err)
		connInfo.DecrementDirectTCPIPCount()
		return
	}

	tcpipInfo.username = connInfo.user.Username
	tcpipInfo.directTCPIPId = fmt.Sprintf("pf-%s-%d", connInfo.proxyFullID, channel.LocalID())

	connInfo.directTCPIP.Store(tcpipInfo.directTCPIPId, tcpipInfo)
	s.log.Debug().Msgf("Stored port forward %s in storage (count: %d)",
		tcpipInfo.directTCPIPId, connInfo.GetDirectTCPIPCount())

	s.log.Debug().Msgf("Direct TCP/IP request: %s:%d -> %s:%d for user %s",
		tcpipInfo.originHost, tcpipInfo.originPort,
		tcpipInfo.destHost, tcpipInfo.destPort,
		connInfo.user.Username)

	defer func() {
		channel.Close()
		if tcpipInfo.directTCPIPId != "" {
			connInfo.directTCPIP.Delete(tcpipInfo.directTCPIPId)
			connInfo.DecrementDirectTCPIPCount()
			s.log.Debug().Msgf("Removed port forward %s from storage (count: %d)",
				tcpipInfo.directTCPIPId, connInfo.GetDirectTCPIPCount())
		}
	}()

	go ssh.DiscardRequests(requests)

	k8shelld, err := connInfo.Handshake(nil, nil, s.provisioner, []string{})
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for user %s: %v", connInfo.user.Username, err)
		return
	}

	s.log.Debug().Msgf("Starting port forward %s for user %s: %s:%d",
		tcpipInfo.directTCPIPId, connInfo.user.Username, tcpipInfo.destHost, tcpipInfo.destPort)

	if err := k8shelld.StartPortForward(connInfo.ctx, channel, tcpipInfo.directTCPIPId,
		tcpipInfo.destHost, tcpipInfo.destPort); err != nil {
		s.log.Error().Msgf("Port forward failed for user %s: %v", connInfo.user.Username, err)
	} else {
		s.log.Debug().Msgf("Port forward %s completed for user %s", tcpipInfo.directTCPIPId, connInfo.user.Username)
	}
}

// parseDirectTCPIPPayload parses the direct-tcpip channel request payload
func parseDirectTCPIPPayload(payload []byte) (*DirectTCPIP, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("payload too short")
	}
	offset := 0

	destHostLen := binary.BigEndian.Uint32(payload[offset : offset+4])
	offset += 4
	if len(payload) < offset+int(destHostLen) {
		return nil, fmt.Errorf("invalid destination host length")
	}
	destHost := string(payload[offset : offset+int(destHostLen)])
	offset += int(destHostLen)

	if len(payload) < offset+4 {
		return nil, fmt.Errorf("missing destination port")
	}
	destPort := binary.BigEndian.Uint32(payload[offset : offset+4])
	offset += 4

	if len(payload) < offset+4 {
		return nil, fmt.Errorf("missing origin host length")
	}
	originHostLen := binary.BigEndian.Uint32(payload[offset : offset+4])
	offset += 4
	if len(payload) < offset+int(originHostLen) {
		return nil, fmt.Errorf("invalid origin host length")
	}
	originHost := string(payload[offset : offset+int(originHostLen)])
	offset += int(originHostLen)

	if len(payload) < offset+4 {
		return nil, fmt.Errorf("missing origin port")
	}
	originPort := binary.BigEndian.Uint32(payload[offset : offset+4])

	return &DirectTCPIP{
		destHost:   destHost,
		destPort:   destPort,
		originHost: originHost,
		originPort: originPort,
	}, nil
}
