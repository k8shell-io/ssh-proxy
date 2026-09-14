// Copyright 2026 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"testing"

	commonv1 "github.com/k8shell-io/common/pkg/api/gen/go/common/v1"
	log "github.com/k8shell-io/common/pkg/logger"
)

func TestSSHProxyServiceGetVersionInfo(t *testing.T) {
	logger := log.NewLogger("test")
	svc := NewSSHProxyService(&Server{log: logger})

	resp, err := svc.GetVersionInfo(context.Background(), &commonv1.GetVersionInfoRequest{})
	if err != nil {
		t.Fatalf("GetVersionInfo returned error: %v", err)
	}

	if resp.GetVersion() != SSHPROXY_VERSION {
		t.Errorf("version = %q, want %q", resp.GetVersion(), SSHPROXY_VERSION)
	}
	if resp.GetCommitId() != SSHPROXY_COMMIT {
		t.Errorf("commit_id = %q, want %q", resp.GetCommitId(), SSHPROXY_COMMIT)
	}
	if resp.GetDescription() == "" {
		t.Error("description is empty")
	}
}
