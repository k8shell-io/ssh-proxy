// Copyright 2026 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"

	commonv1 "github.com/k8shell-io/common/pkg/api/gen/go/common/v1"
	sshproxyv1 "github.com/k8shell-io/common/pkg/api/gen/go/sshproxy/v1"
	"github.com/rs/zerolog"
)

// sshProxyDescription is the short human-readable summary of what this
// service does, returned by GetVersionInfo.
const sshProxyDescription = "Terminates SSH for k8shell workspaces and proxies channel traffic to the in-workspace k8shelld daemon."

// SSHProxyService implements the sshproxy.v1 gRPC service.
type SSHProxyService struct {
	server *Server
	log    *zerolog.Logger
	sshproxyv1.UnimplementedSSHProxyServiceServer
}

// NewSSHProxyService returns a new SSHProxyService.
func NewSSHProxyService(server *Server) *SSHProxyService {
	return &SSHProxyService{
		server: server,
		log:    server.log,
	}
}

// GetVersionInfo returns build and version metadata for this service: its
// released semantic version, the git commit it was built from, and a short
// description of what the service does.
func (s *SSHProxyService) GetVersionInfo(
	_ context.Context, _ *commonv1.GetVersionInfoRequest,
) (*commonv1.GetVersionInfoResponse, error) {
	return &commonv1.GetVersionInfoResponse{
		Version:     SSHPROXY_VERSION,
		CommitId:    SSHPROXY_COMMIT,
		Description: sshProxyDescription,
	}, nil
}
