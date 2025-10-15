// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package workspace

import (
	"fmt"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	pb "github.com/k8shell-io/k8shelld/pkg/api/k8shelldpb"
)

// K8shelld_v12 wraps K8shelld_v11 and overrides specific methods
type K8shelld_v12 struct {
	K8shelldClient
	cfg gapi.ClientConfig
	v11 *K8shelld_v11
}

func NewK8shelld_v12(cfg gapi.ClientConfig, status *models.WorkspaceStatus, counters *ConnCounters) K8shelldClient {
	v11 := NewK8shelld_v11(status, counters).(*K8shelld_v11)
	cfg.Address = fmt.Sprintf("%s:%d", status.PodIP, status.Port)

	return &K8shelld_v12{
		K8shelldClient: v11,
		cfg:            cfg,
		v11:            v11,
	}
}

func (c *K8shelld_v12) Connect() error {
	gapiClient, err := gapi.NewClient(c.cfg)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}

	c.v11.systemClient = pb.NewSystemServiceClient(gapiClient.Conn)
	c.v11.shellClient = pb.NewShellServiceClient(gapiClient.Conn)
	c.v11.execClient = pb.NewExecServiceClient(gapiClient.Conn)
	c.v11.pfClient = pb.NewPortForwardServiceClient(gapiClient.Conn)
	c.v11.unixSocketClient = pb.NewUnixSocketServiceClient(gapiClient.Conn)

	return nil
}
