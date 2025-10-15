// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package workspace

import (
	"fmt"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/k8shelld/pkg/api"
)

// K8shelld_v12 wraps K8shelld_v11 and overrides specific methods
type K8shelld_v12 struct {
	K8shelldClient
	v12 *api.K8shelld
}

func NewK8shelld_v12(cfg gapi.ClientConfig, status *models.WorkspaceStatus,
	counters *api.ConnCounters) (K8shelldClient, error) {
	cfg.Address = fmt.Sprintf("%s:%d", status.PodIP, status.Port)

	v12, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create v12 client: %w", err)
	}

	return &K8shelld_v12{
		K8shelldClient: v12,
		v12:            v12,
	}, nil
}
