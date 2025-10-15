// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package workspace

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	pb "github.com/k8shell-io/k8shelld/pkg/api/k8shelldpb"
	"golang.org/x/crypto/ssh"
)

type K8shelldClient interface {
	Connect() error
	Close() error
	Handshake(ctx context.Context, user *models.User, envVars []string) (*pb.HandshakeResponse, error)
	RunShell(ctx context.Context, channel ssh.Channel, sessionId string, envVars []string,
		width, height uint32, usePty bool) error
	ResizeTerminal(ctx context.Context, sessionId string, width, height uint32) error
	RunUnixSocket(ctx context.Context, channel ssh.Channel, agentUnixID, socketPath string) error
	RunPortForward(ctx context.Context, channel ssh.Channel, portForwardID, destinationIP string,
		destinationPort uint32) error
	RunExec(ctx context.Context, channel ssh.Channel, execID string, command string, shellBinary string,
		envVars []string, signalChan <-chan string) (int32, error)
}

// ConnCounters holds counters for bytes sent and received.
type ConnCounters struct {
	inTotal  int64
	outTotal int64
}

// AddIn adds to the incoming byte counter.
func (c *ConnCounters) AddIn(n int) { atomic.AddInt64(&c.inTotal, int64(n)) }

// AddOut adds to the outgoing byte counter.
func (c *ConnCounters) AddOut(n int) { atomic.AddInt64(&c.outTotal, int64(n)) }

// Snapshot returns the current values of the incoming and outgoing byte counters.
func (c *ConnCounters) Snapshot() (in, out int64) {
	return atomic.LoadInt64(&c.inTotal), atomic.LoadInt64(&c.outTotal)
}

// KEEPALIVE_TIME defines the time for keepalive pings.
var KEEPALIVE_TIME = 5 * time.Minute

// KEEPALIVE_TIMEOUT defines the timeout for keepalive pings.
var KEEPALIVE_TIMEOUT = 20 * time.Second

// NewK8shelld creates a new K8shelld client.
func NewK8shelld(cfg gapi.ClientConfig, status *models.WorkspaceStatus, version string,
	counters *ConnCounters) (K8shelldClient, error) {
	if strings.HasPrefix(version, "0.11") {
		return NewK8shelld_v11(status, counters), nil
	}

	if strings.HasPrefix(version, "0.12") {
		return NewK8shelld_v12(cfg, status, counters), nil
	}

	return nil, fmt.Errorf("unsupported k8shelld version: %s", version)
}
