// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package workspace

import (
	"context"
	"io"
	"time"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/k8shelld/pkg/api"
	pb "github.com/k8shell-io/k8shelld/pkg/api/k8shelldpb"
	"golang.org/x/crypto/ssh"
)

type K8shelldClient interface {
	Handshake(ctx context.Context) (*pb.HandshakeResponse, error)
	RunShell(ctx context.Context, upstream api.BufferedReadWriter, sessionId string, envVars []string,
		width, height uint32, usePty bool, user string) error
	ResizeTerminal(ctx context.Context, sessionId string, width, height uint32) error
	RunUnixSocket(ctx context.Context, upstream api.BufferedReadWriter, unixSocketId, socketPath, mode string) error
	RunPortForward(ctx context.Context, upstream api.BufferedReadWriter, portForwardID, destinationIP string,
		destinationPort uint32) error
	RunExec(ctx context.Context, upstream api.BufferedReadWriter, execID string, command string, shellBinary string,
		envVars []string, signalChan <-chan string) (int32, error)
	RunCommandProcessor(ctx context.Context, handler api.CommandHandler) error
	Close() error
}

// ChannelAdapter adapts ssh.Channel to BufferedReadWriter interface
type ChannelAdapter struct {
	ssh.Channel
}

// ReadBufferSize returns the read buffer size
func (ca *ChannelAdapter) ReadBufferSize() (int, error) {
	return ca.Channel.ReadBufferSize()
}

// Stderr returns the stderr writer
func (ca *ChannelAdapter) Stderr() io.Writer {
	return ca.Channel.Stderr()
}

// KEEPALIVE_TIME defines the time for keepalive pings.
var KEEPALIVE_TIME = 5 * time.Minute

// KEEPALIVE_TIMEOUT defines the timeout for keepalive pings.
var KEEPALIVE_TIMEOUT = 20 * time.Second

// NewK8shelld creates a new K8shelld client.
func NewK8shelld(cfg gapi.ClientConfig, status *models.WorkspaceDetails,
	counters *api.ConnCounters) (K8shelldClient, error) {
	return NewK8shelld_v12(cfg, status, counters)
}
