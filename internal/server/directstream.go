package server

import (
	"encoding/binary"
	"fmt"

	"github.com/k8shell-io/ssh-proxy/internal/workspace"
	"golang.org/x/crypto/ssh"
)

func (s *Server) handleDirectStreamLocal(_ *ssh.ServerConn, connInfo *Connection, newChannel ssh.NewChannel) {
	// Payload: string path, string reserved (ignored)
	path, _, ok := readSSHString(newChannel.ExtraData(), 0)
	if !ok || path == "" {
		newChannel.Reject(ssh.Prohibited, "bad direct-streamlocal payload")
		return
	}

	ch, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)

	k8shelld, err := connInfo.Handshake(nil, nil, s.provisioner, []string{})
	if err != nil {
		s.log.Error().Msgf("Failed to get k8shelld client for user %s: %v", connInfo.user.Username, err)
		return
	}

	uxID := fmt.Sprintf("ux-%s-%s-%d", connInfo.proxyFullID, connInfo.connID, connInfo.ExecSeqNumber())
	if err := k8shelld.RunUnixSocket(connInfo.ctx, &workspace.ChannelAdapter{Channel: ch},
		uxID, path, "UNIX_SOCKET_MODE_DIAL"); err != nil {
		s.log.Error().Err(err).Msg("unix socket connect failed")
		_ = ch.Close()
		return
	}
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
