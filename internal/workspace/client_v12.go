// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package workspace

import (
	"fmt"
	"os"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/k8shelld/pkg/api"
)

// K8shelld_v12 wraps K8shelld_v11 and overrides specific methods
type K8shelld_v12 struct {
	K8shelldClient
}

func NewK8shelld_v12(cfg gapi.ClientConfig, status *models.WorkspaceDetails,
	counters *api.ConnCounters) (K8shelldClient, error) {
	cfg.Address = fmt.Sprintf("%s:%d", status.PodIP, status.Port)
	cfg.ServerName = status.ServerName

	// when the server has TLS cert configured, it means the connection is using TLS
	// so we need to set the CA cert path
	if status.TLSEnabled {
		cfg.CACertPath = "/etc/k8shell/ca/ca.crt"

		if _, err := os.Stat(cfg.CACertPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("the workspace requires TLS but ssh proxy does not have the TLS CA cert at %s",
				cfg.CACertPath)
		}
	}

	v12, err := api.NewClient(cfg, counters)
	if err != nil {
		return nil, fmt.Errorf("failed to create v12 client: %w", err)
	}

	return &K8shelld_v12{
		K8shelldClient: v12,
	}, nil
}
