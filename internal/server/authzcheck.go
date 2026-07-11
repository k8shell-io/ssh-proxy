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
	protoReq := req.ToProto(token)
	protoReq.Package = "ssh"
	resp, err := s.authzClient.Evaluate(ctx, protoReq)
	if err != nil {
		return fmt.Errorf("authz: evaluate %s: %w", req.Action, err)
	}
	if !resp.GetAllowed() {
		return fmt.Errorf("action %q denied: %s", req.Action, resp.GetReason())
	}
	return nil
}

// checkSessionAuthz evaluates a session:start request and returns the recording
// obligation from the policy engine. When authz is not configured, returns
// (zero, false, nil) so callers fall back to their configured defaults.
func (s *Server) checkSessionAuthz(ctx context.Context, token string, req *authz.SessionStartEvalRequest) (authz.RecordObligation, bool, error) {
	if s.authzClient == nil {
		return authz.RecordObligation{}, false, nil
	}
	if err := req.Validate(); err != nil {
		return authz.RecordObligation{}, false, fmt.Errorf("authz: invalid request: %w", err)
	}
	protoReq := req.ToProto(token)
	protoReq.Package = "session"
	resp, err := s.authzClient.Evaluate(ctx, protoReq)
	if err != nil {
		return authz.RecordObligation{}, false, fmt.Errorf("authz: evaluate %s: %w", req.Action, err)
	}
	if !resp.GetAllowed() {
		return authz.RecordObligation{}, false, fmt.Errorf("action %q denied: %s", req.Action, resp.GetReason())
	}
	ob, found := authz.ParseRecordObligation(resp.GetObligations())
	return ob, found, nil
}

// checkUserAuthMethodsAuthz evaluates a user:auth request against the authz
// service and returns the auth_methods obligation naming which SSH
// authentication methods the policy permits for the user. When authz is not
// configured, returns (zero, false, nil) so callers fall back to their own
// default. When authz is configured but the response carries no auth_methods
// obligation, found is false and, per the user:auth contract, the caller must
// offer no authentication methods.
func (s *Server) checkUserAuthMethodsAuthz(ctx context.Context, token string, req *authz.UserAuthEvalRequest) (authz.AuthMethodsObligation, bool, error) {
	if s.authzClient == nil {
		return authz.AuthMethodsObligation{}, false, nil
	}
	if err := req.Validate(); err != nil {
		return authz.AuthMethodsObligation{}, false, fmt.Errorf("authz: invalid request: %w", err)
	}
	protoReq := req.ToProto(token)
	protoReq.Package = "user"
	resp, err := s.authzClient.Evaluate(ctx, protoReq)
	if err != nil {
		return authz.AuthMethodsObligation{}, false, fmt.Errorf("authz: evaluate user:auth: %w", err)
	}
	if !resp.GetAllowed() {
		return authz.AuthMethodsObligation{}, false, fmt.Errorf("user:auth denied: %s", resp.GetReason())
	}
	ob, found := authz.ParseAuthMethodsObligation(resp.GetObligations())
	return ob, found, nil
}
