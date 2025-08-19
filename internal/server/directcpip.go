package server

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Maximum number of direct TCP/IP connections allowed (per ssh connection)
const MAX_DIRECT_TCPIP_CONNECTIONS = 12

// handleDirectTCPIPChannel handles a new direct TCP/IP channel request
func (s *Server) handleDirectTCPIPChannel(_ *ssh.ServerConn, connInfo *ConnectionInfo, newChannel ssh.NewChannel) {
	if !connInfo.IncrementDirectTCPIPCount(MAX_DIRECT_TCPIP_CONNECTIONS) {
		s.log.Warn().Msgf("User %s exceeded max direct-tcpip connections (limit: %d)",
			connInfo.User.Username, MAX_DIRECT_TCPIP_CONNECTIONS)
		newChannel.Reject(ssh.ResourceShortage,
			fmt.Sprintf("maximum direct-tcpip connections exceeded (%d)", MAX_DIRECT_TCPIP_CONNECTIONS))
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

	tcpipInfo.Username = connInfo.User.Username
	tcpipInfo.DirectTCPIPId = fmt.Sprintf("pf-%s-%d", connInfo.proxyID, channel.LocalID())

	connInfo.DirectTCPIP.Store(tcpipInfo.DirectTCPIPId, tcpipInfo)
	s.log.Debug().Msgf("Stored port forward %s in storage (count: %d)",
		tcpipInfo.DirectTCPIPId, connInfo.GetDirectTCPIPCount())

	s.log.Debug().Msgf("Direct TCP/IP request: %s:%d -> %s:%d for user %s",
		tcpipInfo.OriginHost, tcpipInfo.OriginPort,
		tcpipInfo.DestHost, tcpipInfo.DestPort,
		connInfo.User.Username)

	defer func() {
		channel.Close()
		if tcpipInfo.DirectTCPIPId != "" {
			connInfo.DirectTCPIP.Delete(tcpipInfo.DirectTCPIPId)
			connInfo.DecrementDirectTCPIPCount()
			s.log.Debug().Msgf("Removed port forward %s from storage (count: %d)",
				tcpipInfo.DirectTCPIPId, connInfo.GetDirectTCPIPCount())
		}
	}()

	go ssh.DiscardRequests(requests)

	k8shelld, err := connInfo.CreateK8shelldClient(s.ctx, channel, s.provisioner)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for user %s: %v", connInfo.User.Username, err)
		return
	}

	s.log.Debug().Msgf("Starting port forward %s for user %s: %s:%d",
		tcpipInfo.DirectTCPIPId, connInfo.User.Username, tcpipInfo.DestHost, tcpipInfo.DestPort)

	if err := k8shelld.StartPortForward(s.ctx, channel, tcpipInfo.DirectTCPIPId,
		tcpipInfo.DestHost, tcpipInfo.DestPort); err != nil {
		s.log.Error().Msgf("Port forward failed for user %s: %v", connInfo.User.Username, err)
	} else {
		s.log.Debug().Msgf("Port forward %s completed for user %s", tcpipInfo.DirectTCPIPId, connInfo.User.Username)
	}
}

// parseDirectTCPIPPayload parses the direct-tcpip channel request payload
func parseDirectTCPIPPayload(payload []byte) (*DirectTCPIPInfo, error) {
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

	return &DirectTCPIPInfo{
		DestHost:   destHost,
		DestPort:   destPort,
		OriginHost: originHost,
		OriginPort: originPort,
	}, nil
}
