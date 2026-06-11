// Copyright 2026 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"fmt"

	"github.com/k8shell-io/common/pkg/authz"
)

// checkSSHAuthz evaluates an SSH authz request against the authz service.
// Returns nil when authz is not configured (opt-in) or when the action is allowed.
func (s *Server) checkSSHAuthz(ctx context.Context, token string, req *authz.SSHEvalRequest) error {
	if s.authzClient == nil {
		return nil
	}
	if err := req.Validate(); err != nil {
		return fmt.Errorf("authz: invalid request: %w", err)
	}
	resp, err := s.authzClient.Evaluate(ctx, req.ToProto(token))
	if err != nil {
		return fmt.Errorf("authz: evaluate %s: %w", req.Action, err)
	}
	if !resp.GetAllowed() {
		return fmt.Errorf("action %q denied: %s", req.Action, resp.GetReason())
	}
	return nil
}
