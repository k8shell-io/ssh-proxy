// Copyright 2026 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/k8shell-io/common/pkg/authz"
	natsc "github.com/k8shell-io/common/pkg/nats"
)

// kvGetter is the read side of a JetStream KV bucket (natsc.JetStreamKV).
type kvGetter interface {
	Get(key string) (nats.KeyValueEntry, error)
}

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

// CheckWorkspaceCreateAuthz evaluates a workspace:create request against the
// authz service, the same check api-server's HTTP create route performs
// before calling ProvisionHandshake. Returns nil when authz is not configured
// (opt-in) or when the action is allowed. Backends interface implementation.
func (s *Server) CheckWorkspaceCreateAuthz(ctx context.Context, token string, req *authz.WorkspaceOwnerEvalRequest) error {
	if s.authzClient == nil {
		return nil
	}
	if err := req.Validate(); err != nil {
		return fmt.Errorf("authz: invalid request: %w", err)
	}
	protoReq := req.ToProto(token)
	protoReq.Package = "workspace"
	resp, err := s.authzClient.Evaluate(ctx, protoReq)
	if err != nil {
		return fmt.Errorf("authz: evaluate %s: %w", req.Action, err)
	}
	if !resp.GetAllowed() {
		return fmt.Errorf("action %q denied: %s", req.Action, resp.GetReason())
	}
	return nil
}

// recordingObligation returns the recording obligation for a session. A
// workspace recording override takes precedence over everything else: when
// one exists it is the whole decision and session:record is not evaluated, so
// a policy result or an authz outage cannot change it. Otherwise the obligation
// comes from the policy engine. session:record is not an access check: the
// ssh:* entry checks are the only gate, so PolicyResult.Allowed is ignored
// here. When authz is not configured, or the policy returns no record
// obligation, found is false and callers fall back to their configured
// defaults. An evaluate error is returned so callers fail closed rather than
// silently skipping recording.
func (s *Server) recordingObligation(ctx context.Context, token string, req *authz.SessionRecordEvalRequest) (authz.RecordObligation, bool, error) {
	if override := s.recordingOverride(req.Resource.ID); override != nil {
		ob, found := natsc.ResolveRecordObligation(authz.RecordObligation{}, false, override)
		return ob, found, nil
	}
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
	ob, found := authz.ParseRecordObligation(resp.GetObligations())
	return ob, found, nil
}

// recordingOverride reads the workspace's entry in RECORDING_OVERRIDES_BUCKET.
// It is read fresh for every session so a changed override applies to sessions
// started afterwards. Returns nil when there is no override, and fails open to
// the policy result (nil) when the bucket is unavailable or the value does not
// decode, so a NATS outage never blocks SSH sessions.
func (s *Server) recordingOverride(workspace string) *natsc.RecordingOverride {
	if s.recordingOverridesKV == nil || workspace == "" {
		return nil
	}
	entry, err := s.recordingOverridesKV.Get(workspace)
	if errors.Is(err, nats.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		s.log.Error().Err(err).Str("workspace", workspace).Msg("Failed to read recording override; using policy")
		return nil
	}
	var o natsc.RecordingOverride
	if err := json.Unmarshal(entry.Value(), &o); err != nil {
		s.log.Error().Err(err).Str("workspace", workspace).Msg("Invalid recording override; using policy")
		return nil
	}
	s.log.Info().Str("workspace", workspace).Str("record", o.Record).Str("setBy", o.SetBy).
		Msg("Applying recording override")
	return &o
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

// openRecordingOverrides opens RECORDING_OVERRIDES_BUCKET with the same options
// api-server uses, so whichever service starts first creates it identically.
// The bucket must not expire entries: a zero BucketTTL would mean 24h.
func (s *Server) openRecordingOverrides() error {
	kv, err := s.nats.NewKV(natsc.BucketOptions{
		Bucket:    natsc.RECORDING_OVERRIDES_BUCKET,
		BucketTTL: natsc.NoBucketTTL,
	})
	if err != nil {
		return fmt.Errorf("open recording overrides bucket: %w", err)
	}
	s.recordingOverridesKV = kv
	return nil
}
