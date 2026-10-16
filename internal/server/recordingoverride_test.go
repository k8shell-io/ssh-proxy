// Copyright 2026 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	"github.com/k8shell-io/common/pkg/authz"
	natsc "github.com/k8shell-io/common/pkg/nats"
)

// fakeKVEntry carries only a value; embedding the interface leaves the other
// methods unimplemented, and recordingOverride never calls them.
type fakeKVEntry struct {
	nats.KeyValueEntry
	value []byte
}

func (e fakeKVEntry) Value() []byte { return e.value }

// fakeOverridesKV is an in-memory RECORDING_OVERRIDES_BUCKET.
type fakeOverridesKV struct {
	values map[string][]byte
	err    error
	gets   []string
}

func (f *fakeOverridesKV) Get(key string) (nats.KeyValueEntry, error) {
	f.gets = append(f.gets, key)
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.values[key]
	if !ok {
		return nil, nats.ErrKeyNotFound
	}
	return fakeKVEntry{value: v}, nil
}

func overrideKV(t *testing.T, workspace, record string) *fakeOverridesKV {
	t.Helper()
	v, err := json.Marshal(natsc.RecordingOverride{Record: record, SetBy: "admin", SetAt: 1791273600})
	if err != nil {
		t.Fatal(err)
	}
	return &fakeOverridesKV{values: map[string][]byte{workspace: v}}
}

// policy returns an authz fake whose session:record evaluation yields the
// given record obligation ("" for none).
func policy(record string) *fakeAuthzClient {
	resp := &authzv1.EvaluateResponse{Allowed: true}
	if record != "" {
		resp.Obligations = map[string]string{authz.ObligationKeyRecord: record}
	}
	return &fakeAuthzClient{resp: map[string]*authzv1.EvaluateResponse{"session": resp}}
}

func newOverrideTestServer(authzClient *fakeAuthzClient, kv *fakeOverridesKV) *Server {
	log := zerolog.Nop()
	s := &Server{log: &log}
	if authzClient != nil {
		s.authzClient = authzClient
	}
	if kv != nil {
		s.recordingOverridesKV = kv
	}
	return s
}

func recordReq(workspace string, typ authz.SessionType) *authz.SessionRecordEvalRequest {
	return authz.NewSessionRecordEvalRequest(authz.SessionActionRecord, workspace, typ).
		WithSource(authz.SessionSourceSSHProxy).
		WithOwner("alice").
		WithBlueprint("ubuntu")
}

var allSessionTypes = []authz.SessionType{
	authz.SessionTypeShell, authz.SessionTypeExec, authz.SessionTypeSFTP, authz.SessionTypeTCPIP,
}

func TestRecordingOverrideAbsentKeepsPolicy(t *testing.T) {
	for _, typ := range allSessionTypes {
		kv := &fakeOverridesKV{}
		s := newOverrideTestServer(policy("shell,exec,sftp,direct-tcpip"), kv)

		ob, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", typ))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", typ, err)
		}
		want := authz.RecordObligation{Shell: true, Exec: true, SFTP: true, DirectTCPIP: true}
		if !found || ob != want {
			t.Fatalf("%s: expected policy result %+v, got found=%v ob=%+v", typ, want, found, ob)
		}
		if len(kv.gets) != 1 || kv.gets[0] != "ws1" {
			t.Fatalf("%s: expected one Get for ws1, got %v", typ, kv.gets)
		}
	}
}

func TestRecordingOverrideAbsentNoPolicyUsesDefault(t *testing.T) {
	s := newOverrideTestServer(policy(""), &fakeOverridesKV{})
	_, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeShell))
	if err != nil || found {
		t.Fatalf("expected found=false so the configured default applies, got found=%v err=%v", found, err)
	}
}

// The override replaces the policy result entirely: types it does not list
// are not recorded even when policy would record them.
func TestRecordingOverrideReplacesPolicy(t *testing.T) {
	s := newOverrideTestServer(policy("shell,exec"), overrideKV(t, "ws1", "shell"))

	ob, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeExec))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || !ob.Shell || ob.Exec {
		t.Fatalf("expected shell only, got found=%v ob=%+v", found, ob)
	}
}

// "none" counts as found, so callers do not fall back to their configured
// defaults (including direct-tcpip's static recording config).
func TestRecordingOverrideNoneSuppressesDefault(t *testing.T) {
	s := newOverrideTestServer(policy("shell"), overrideKV(t, "ws1", authz.ObligationRecordNone))

	ob, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeTCPIP))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || ob != (authz.RecordObligation{}) {
		t.Fatalf("expected found=true with nothing recorded, got found=%v ob=%+v", found, ob)
	}

	cfg := RecordingConfig{RecordShell: true, RecordExec: true, RecordSFTP: true, RecordDirectTCPIP: true}
	cfg.DirectTCPIP.Vscode.Terminals = boolPtr(true)
	if record, _ := cfg.tcpipRecording(&ob); record {
		t.Fatal("override none must disable direct-tcpip recording despite the static config")
	}
}

func TestRecordingOverrideAppliesWithoutPolicyObligation(t *testing.T) {
	s := newOverrideTestServer(policy(""), overrideKV(t, "ws1", "sftp"))

	ob, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeSFTP))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || !ob.SFTP || ob.Shell {
		t.Fatalf("expected sftp only, got found=%v ob=%+v", found, ob)
	}
}

func TestRecordingOverrideAppliesWithoutAuthz(t *testing.T) {
	s := newOverrideTestServer(nil, overrideKV(t, "ws1", "exec"))

	ob, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeExec))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || !ob.Exec || ob.Shell {
		t.Fatalf("expected exec only, got found=%v ob=%+v", found, ob)
	}
}

func TestRecordingOverrideOtherWorkspaceIgnored(t *testing.T) {
	s := newOverrideTestServer(policy("shell"), overrideKV(t, "ws2", authz.ObligationRecordNone))

	ob, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeShell))
	if err != nil || !found || !ob.Shell {
		t.Fatalf("expected ws1 policy result, got found=%v ob=%+v err=%v", found, ob, err)
	}
}

// A KV outage or a bad value fails open to the policy result.
func TestRecordingOverrideReadFailureUsesPolicy(t *testing.T) {
	cases := map[string]*fakeOverridesKV{
		"get error":   {err: errors.New("nats: timeout")},
		"bad value":   {values: map[string][]byte{"ws1": []byte("{not json")}},
		"closed conn": {err: nats.ErrConnectionClosed},
	}
	for name, kv := range cases {
		s := newOverrideTestServer(policy("shell"), kv)
		ob, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeShell))
		if err != nil {
			t.Fatalf("%s: session must proceed, got error: %v", name, err)
		}
		if !found || !ob.Shell {
			t.Fatalf("%s: expected policy result, got found=%v ob=%+v", name, found, ob)
		}
	}
}

// The override takes precedence over anything policy would provide: when one
// exists session:record is not evaluated, so an authz outage cannot reject it.
func TestRecordingOverrideSkipsPolicyEvaluation(t *testing.T) {
	fake := &fakeAuthzClient{err: map[string]error{"session": errors.New("unavailable")}}
	s := newOverrideTestServer(fake, overrideKV(t, "ws1", "shell"))

	ob, found, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeShell))
	if err != nil {
		t.Fatalf("override must apply despite the Evaluate error, got: %v", err)
	}
	if !found || !ob.Shell {
		t.Fatalf("expected shell only, got found=%v ob=%+v", found, ob)
	}
	if len(fake.reqs) != 0 {
		t.Fatalf("session:record must not be evaluated when an override exists, got %d calls", len(fake.reqs))
	}
}

// Without an override, an Evaluate error still fails closed.
func TestRecordingOverrideAbsentEvaluateErrorFailsClosed(t *testing.T) {
	fake := &fakeAuthzClient{err: map[string]error{"session": errors.New("unavailable")}}
	s := newOverrideTestServer(fake, &fakeOverridesKV{})

	if _, _, err := s.recordingObligation(context.Background(), "tok", recordReq("ws1", authz.SessionTypeShell)); err == nil {
		t.Fatal("expected Evaluate error to reject the session")
	}
}
