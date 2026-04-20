package server

import (
	"encoding/binary"
	"fmt"

	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"golang.org/x/crypto/ssh"
)

type StreamLocal struct {
	username      string // username of the user
	streamLocalId string // unique identifier for the stream local connection
	destPath      string // destination path
}

func (s *Server) handleDirectStreamLocal(_ *ssh.ServerConn, connInfo *Connection, newChannel ssh.NewChannel) {
	streamLocal, err := parseDirectStreamLocalPayload(newChannel.ExtraData())
	if err != nil || streamLocal == nil {
		err := newChannel.Reject(ssh.Prohibited, "bad direct-streamlocal payload")
		if err != nil {
			s.log.Error().Msgf("Failed to reject direct-streamlocal channel: %v", err)
		}
		return
	}

	streamLocal.username = connInfo.user.Username
	streamLocal.streamLocalId = fmt.Sprintf("ux-%s%d", connInfo.connId, connInfo.SeqNumber())

	ch, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() {
		_ = ch.Close()
		s.log.Debug().Msgf("Closed direct-streamlocal channel for user %s", connInfo.user.Username)
	}()
	go ssh.DiscardRequests(reqs)

	k8shelld, err := connInfo.Handshake(nil, nil, s)
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for user %s: %v", connInfo.user.Username, err)
		return
	}

	userToken, err := connInfo.GetUserToken()
	if err != nil {
		s.log.Error().Msgf("Failed to get user token for user %s: %v", connInfo.user.Username, err)
		return
	}

	if err := k8shelld.RunUnixSocket(connInfo.ctx, userToken, &workspace.ChannelAdapter{Channel: ch},
		streamLocal.streamLocalId, streamLocal.destPath, "UNIX_SOCKET_MODE_DIAL"); err != nil {
		s.log.Error().Err(err).Msg("unix socket connect failed")
		return
	}
}

// parseDirectStreamLocalPayload parses the direct-streamlocal channel request payload
func parseDirectStreamLocalPayload(b []byte) (*StreamLocal, error) {
	off := 0

	p, _, ok := readSSHString(b, off)
	if !ok || p == "" {
		return nil, fmt.Errorf("invalid direct-streamlocal payload: missing path")
	}

	return &StreamLocal{
		destPath: p,
	}, nil
}

// readSSHString parses an SSH "string" from b starting at off.
func readSSHString(b []byte, off int) (string, int, bool) {
	if len(b) < off+4 {
		return "", off, false
	}
	n := int(binary.BigEndian.Uint32(b[off:]))
	off += 4
	if n < 0 || len(b) < off+n {
		return "", off, false
	}
	return string(b[off : off+n]), off + n, true
}
