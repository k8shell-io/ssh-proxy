// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"encoding/binary"
	"fmt"

	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"golang.org/x/crypto/ssh"
)

// DirectTCPIP holds information about a direct TCP/IP connection
type DirectTCPIP struct {
	username      string // username of the user
	directTCPIPId string // unique identifier for the direct TCP/IP connection
	destHost      string // destination host
	destPort      uint32 // destination port
	originHost    string // origin host
	originPort    uint32 // origin port
}

// handleDirectTCPIPChannel handles a new direct TCP/IP channel request
func (s *Server) handleDirectTCPIPChannel(_ *ssh.ServerConn, connInfo *Connection, newChannel ssh.NewChannel) {
	if !connInfo.IncrementDirectTCPIPCount(s.Config.Server.MaxDirectTCPIPConnections) {
		s.log.Warn().Msgf("User %s exceeded max direct-tcpip connections (limit: %d)",
			connInfo.user.Username, s.Config.Server.MaxDirectTCPIPConnections)
		err := newChannel.Reject(ssh.ResourceShortage,
			fmt.Sprintf("maximum direct-tcpip connections exceeded (%d)", s.Config.Server.MaxDirectTCPIPConnections))
		if err != nil {
			s.log.Error().Msgf("Failed to reject direct-tcpip channel: %v", err)
		}
		return
	}

	tcpipInfo, err := parseDirectTCPIPPayload(newChannel.ExtraData())
	if err != nil {
		s.log.Error().Msgf("Failed to parse direct-tcpip payload: %v", err)
		err := newChannel.Reject(ssh.UnknownChannelType, "invalid payload")
		if err != nil {
			s.log.Error().Msgf("Failed to reject direct-tcpip channel: %v", err)
		}
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
	tcpipInfo.directTCPIPId = fmt.Sprintf("pf-%s%d", connInfo.connId, connInfo.SeqNumber())

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

	k8shelld, err := connInfo.Handshake(nil, nil, s)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for user %s: %v", connInfo.user.Username, err)
		return
	}

	s.log.Debug().Msgf("Starting port forward %s for user %s: %s:%d",
		tcpipInfo.directTCPIPId, connInfo.user.Username, tcpipInfo.destHost, tcpipInfo.destPort)

	userToken, err := connInfo.GetUserToken()
	if err != nil {
		s.log.Error().Msgf("Failed to get user token for user %s: %v", connInfo.user.Username, err)
		return
	}

	if authzErr := s.checkSSHAuthz(connInfo.ctx, userToken,
		authz.NewSSHEvalRequest(authz.SSHActionDirectTCPIP, connInfo.workspaceName).
			WithOwner(connInfo.user.Username).
			WithHost(tcpipInfo.destHost).
			WithPort(fmt.Sprintf("%d", tcpipInfo.destPort)),
	); authzErr != nil {
		s.log.Warn().Msgf("SSH direct-tcpip denied for user %s: %v", connInfo.user.Username, authzErr)
		return
	}

	rw := &workspace.ChannelAdapter{Channel: channel}
	if err := k8shelld.RunPortForward(connInfo.ctx, userToken, rw,
		tcpipInfo.directTCPIPId, tcpipInfo.originHost, tcpipInfo.originPort, tcpipInfo.destHost,
		tcpipInfo.destPort, s.Config.Server.Recording.RecordDirectTCPIP); err != nil {
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
