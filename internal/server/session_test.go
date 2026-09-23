// Copyright 2026 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"reflect"
	"sort"
	"testing"

	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/userstr"
)

// TestResolveShellBinaryNoHardcodedShFallback guards against regressing to a
// hardcoded "/bin/sh" interpreter for exec requests, which forces dash/ash
// and breaks bash/zsh-only constructs like Warp's SSH bootstrap script
// (`exec -a bash bash --rcfile <(echo '...')`, which uses process
// substitution dash can't parse).
func TestResolveShellBinaryNoHardcodedShFallback(t *testing.T) {
	const newK8shelldVer = "pr-66-3874e67"

	tests := []struct {
		name        string
		user        *models.User
		k8shelldVer string
		want        string
	}{
		{
			name:        "user with a resolved bash login shell",
			user:        &models.User{Username: "liptarob", Shell: "/bin/bash"},
			k8shelldVer: newK8shelldVer,
			want:        "/bin/bash",
		},
		{
			name:        "user with no bash, login shell is /bin/sh",
			user:        &models.User{Username: "liptarob", Shell: "/bin/sh"},
			k8shelldVer: newK8shelldVer,
			want:        "/bin/sh",
		},
		{
			name:        "user with no shell recorded falls back to empty, not /bin/sh",
			user:        &models.User{Username: "liptarob"},
			k8shelldVer: newK8shelldVer,
			want:        "",
		},
		{
			name:        "nil user falls back to empty, not /bin/sh",
			user:        nil,
			k8shelldVer: newK8shelldVer,
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveShellBinary(tt.user, tt.k8shelldVer); got != tt.want {
				t.Errorf("resolveShellBinary(%+v, %q) = %q, want %q", tt.user, tt.k8shelldVer, got, tt.want)
			}
		})
	}
}

// TestResolveShellBinaryPreFixK8shelldGetsExplicitSh guards the rollout
// compatibility shim: a workspace pod still running a k8shelld version that
// predates the login-shell-resolution contract must keep getting an explicit
// "/bin/sh", not empty, since that version's handling of an empty
// shell_binary on exec was never exercised and is unverified.
func TestResolveShellBinaryPreFixK8shelldGetsExplicitSh(t *testing.T) {
	user := &models.User{Username: "liptarob", Shell: "/bin/bash"}

	for oldVer := range preLoginShellExecK8shelldVersions {
		t.Run(oldVer, func(t *testing.T) {
			if got := resolveShellBinary(user, oldVer); got != "/bin/sh" {
				t.Errorf("resolveShellBinary(%+v, %q) = %q, want \"/bin/sh\"", user, oldVer, got)
			}
		})
	}
}

func TestLoginEnvVars(t *testing.T) {
	tests := []struct {
		name   string
		user   *models.User
		asUser string
		want   []string
	}{
		{
			name:   "shell, user and logname all resolved",
			user:   &models.User{Shell: "/bin/bash"},
			asUser: "liptarob",
			want:   []string{"SHELL=/bin/bash", "USER=liptarob", "LOGNAME=liptarob"},
		},
		{
			name:   "no shell known, USER/LOGNAME still set",
			user:   &models.User{},
			asUser: "liptarob",
			want:   []string{"USER=liptarob", "LOGNAME=liptarob"},
		},
		{
			name:   "nil user, USER/LOGNAME still set from asUser",
			user:   nil,
			asUser: "liptarob",
			want:   []string{"USER=liptarob", "LOGNAME=liptarob"},
		},
		{
			name:   "nothing resolved",
			user:   nil,
			asUser: "",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := loginEnvVars(tt.user, tt.asUser)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loginEnvVars(%+v, %q) = %v, want %v", tt.user, tt.asUser, got, tt.want)
			}
		})
	}
}

func TestWithLoginEnvOverridesClientEnv(t *testing.T) {
	// A malicious or naive client sending its own SHELL/USER/LOGNAME via an
	// "env" request must not be able to override the resolved login values,
	// matching sshd (SendEnv can't override these). Unrelated client env
	// (TERM, LC_*, LANG) must still pass through untouched.
	clientEnv := []string{
		"TERM=xterm-256color",
		"SHELL=/bin/zsh",
		"LC_CTYPE=UTF-8",
		"USER=someone-else",
		"LANG=C.UTF-8",
	}
	loginVars := loginEnvVars(&models.User{Shell: "/bin/bash"}, "liptarob")

	got := withLoginEnv(clientEnv, loginVars)

	want := []string{
		"SHELL=/bin/bash",
		"USER=liptarob",
		"LOGNAME=liptarob",
		"TERM=xterm-256color",
		"LC_CTYPE=UTF-8",
		"LANG=C.UTF-8",
	}

	if !sameSet(got, want) {
		t.Errorf("withLoginEnv(%v, %v) = %v, want set %v", clientEnv, loginVars, got, want)
	}

	for _, v := range got {
		if v == "SHELL=/bin/zsh" || v == "USER=someone-else" {
			t.Errorf("withLoginEnv did not override client-supplied %q", v)
		}
	}
}

func TestWithLoginEnvNoLoginVarsReturnsEnvUnchanged(t *testing.T) {
	env := []string{"TERM=xterm-256color"}
	got := withLoginEnv(env, nil)
	if !reflect.DeepEqual(got, env) {
		t.Errorf("withLoginEnv(%v, nil) = %v, want unchanged %v", env, got, env)
	}
}

// TestEffectiveAsUserFallsBackToAuthenticatedUser guards a real bug found by
// inspecting live k8shelld logs: for the common case of a user connecting as
// themselves (no "+user=" override in the userstr), userStr.User() is empty
// (it's only populated for an explicit as-user override), so USER/LOGNAME
// were silently never set. k8shelld runs the command as the authenticated
// user whenever asUser is empty ("empty for default"), so that's what
// USER/LOGNAME should reflect too.
func TestEffectiveAsUserFallsBackToAuthenticatedUser(t *testing.T) {
	implicitUserStr, err := userstr.ParseUserStr("bruckins~dev")
	if err != nil {
		t.Fatalf("ParseUserStr(bruckins~dev) failed: %v", err)
	}
	explicitUserStr, err := userstr.ParseUserStr("bruckins~dev+user=root")
	if err != nil {
		t.Fatalf("ParseUserStr(bruckins~dev+user=root) failed: %v", err)
	}

	tests := []struct {
		name    string
		userStr *userstr.UserStr
		user    *models.User
		want    string
	}{
		{
			name:    "no explicit as-user override falls back to the authenticated user",
			userStr: implicitUserStr,
			user:    &models.User{Username: "bruckins"},
			want:    "bruckins",
		},
		{
			name:    "explicit as-user override wins",
			userStr: explicitUserStr,
			user:    &models.User{Username: "bruckins"},
			want:    "root",
		},
		{
			name:    "no override and no authenticated user known",
			userStr: implicitUserStr,
			user:    nil,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connInfo := &Connection{userStr: tt.userStr, user: tt.user}
			if got := effectiveAsUser(connInfo); got != tt.want {
				t.Errorf("effectiveAsUser(...) = %q, want %q", got, tt.want)
			}
		})
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string{}, a...)
	sb := append([]string{}, b...)
	sort.Strings(sa)
	sort.Strings(sb)
	return reflect.DeepEqual(sa, sb)
}
