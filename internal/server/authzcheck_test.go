// Copyright 2026 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	"github.com/k8shell-io/common/pkg/authz"
)

// fakeAuthzClient answers Evaluate from a per-package table. Embedding the
// interface leaves the other RPCs unimplemented; tests never call them.
type fakeAuthzClient struct {
	authzv1.AuthzServiceClient
	resp map[string]*authzv1.EvaluateResponse
	err  map[string]error
	reqs []*authzv1.EvaluateRequest
}

func (f *fakeAuthzClient) Evaluate(_ context.Context, in *authzv1.EvaluateRequest, _ ...grpc.CallOption) (*authzv1.EvaluateResponse, error) {
	f.reqs = append(f.reqs, in)
	if err := f.err[in.GetPackage()]; err != nil {
		return nil, err
	}
	return f.resp[in.GetPackage()], nil
}

func newRecordReq() *authz.SessionRecordEvalRequest {
	return authz.NewSessionRecordEvalRequest(authz.SessionActionRecord, "ws1", authz.SessionTypeShell).
		WithSource(authz.SessionSourceSSHProxy).
		WithOwner("alice").
		WithBlueprint("ubuntu")
}

func TestRecordingObligationIgnoresAllowed(t *testing.T) {
	fake := &fakeAuthzClient{resp: map[string]*authzv1.EvaluateResponse{
		"session": {Allowed: false, Reason: "no rule", Obligations: map[string]string{
			authz.ObligationKeyRecord: authz.ObligationRecordShell,
		}},
	}}
	s := &Server{authzClient: fake}

	ob, found, err := s.recordingObligation(context.Background(), "tok", newRecordReq())
	if err != nil {
		t.Fatalf("Allowed=false must not refuse the session, got error: %v", err)
	}
	if !found || !ob.Shell {
		t.Fatalf("expected record=shell obligation, got found=%v ob=%+v", found, ob)
	}
	if ob.Exec || ob.DirectTCPIP || ob.SFTP {
		t.Fatalf("unexpected channels recorded: %+v", ob)
	}
	if len(fake.reqs) != 1 || fake.reqs[0].GetAction() != "session:record" || fake.reqs[0].GetPackage() != "session" {
		t.Fatalf("unexpected request: %+v", fake.reqs)
	}
}

func TestRecordingObligationMissingUsesDefault(t *testing.T) {
	fake := &fakeAuthzClient{resp: map[string]*authzv1.EvaluateResponse{
		"session": {Allowed: false},
	}}
	s := &Server{authzClient: fake}

	_, found, err := s.recordingObligation(context.Background(), "tok", newRecordReq())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false when policy returns no record obligation")
	}
}

func TestRecordingObligationEvaluateErrorFailsClosed(t *testing.T) {
	fake := &fakeAuthzClient{err: map[string]error{"session": errors.New("unavailable")}}
	s := &Server{authzClient: fake}

	if _, _, err := s.recordingObligation(context.Background(), "tok", newRecordReq()); err == nil {
		t.Fatal("expected Evaluate error to reject the session")
	}
}

func TestRecordingObligationNoAuthz(t *testing.T) {
	s := &Server{}
	_, found, err := s.recordingObligation(context.Background(), "tok", newRecordReq())
	if err != nil || found {
		t.Fatalf("expected (false, nil) without authz, got found=%v err=%v", found, err)
	}
}

// The ssh:* entry check stays the gate: a denied ssh:shell refuses the
// session no matter what session:record would return.
func TestSSHShellDeniedRegardlessOfRecord(t *testing.T) {
	fake := &fakeAuthzClient{resp: map[string]*authzv1.EvaluateResponse{
		"ssh":     {Allowed: false, Reason: "denied"},
		"session": {Allowed: true, Obligations: map[string]string{authz.ObligationKeyRecord: authz.ObligationRecordShell}},
	}}
	s := &Server{authzClient: fake}

	err := s.checkSSHAuthz(context.Background(), "tok",
		authz.NewSSHEvalRequest(authz.SSHActionShell, "ws1").WithOwner("alice"))
	if err == nil {
		t.Fatal("expected ssh:shell deny to refuse the session")
	}
}
