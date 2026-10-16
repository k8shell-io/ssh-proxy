// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	sessionv1 "github.com/k8shell-io/common/pkg/api/gen/go/session/v1"
	"github.com/k8shell-io/common/pkg/authz"
)

func writeConfig(t *testing.T, recording string) string {
	return writeConfigWith(t, recording, "")
}

func writeConfigWith(t *testing.T, recording, rest string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 2022\n  recording:\n"+recording+rest), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRecordingConfigDecode(t *testing.T) {
	cfg, err := NewConfig(writeConfig(t, `
    recordDirectTCPIP: true
    bufferBytes: 1048576
    shell:
      gzip: true
    directTCPIP:
      format: none
      vscode:
        terminals: true
        recordInput: false
`))
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.Server.Recording.K8shelld()
	if rc.BufferBytes != 1<<20 {
		t.Errorf("BufferBytes = %d", rc.BufferBytes)
	}
	if rc.Exec != nil || rc.Sftp != nil {
		t.Errorf("unset streams must leave options nil: exec=%v sftp=%v", rc.Exec, rc.Sftp)
	}
	if rc.Shell == nil || !rc.Shell.GetGzip() || rc.Shell.Format != sessionv1.RecordingFormat_RECORDING_FORMAT_UNSPECIFIED || rc.Shell.Vscode != nil {
		t.Errorf("shell = %v", rc.Shell)
	}
	tc := rc.Tcpip
	if tc == nil || tc.Format != sessionv1.RecordingFormat_RECORDING_FORMAT_NONE || tc.Gzip != nil {
		t.Fatalf("tcpip = %v", tc)
	}
	if tc.Vscode == nil || tc.Vscode.Terminals == nil || !*tc.Vscode.Terminals ||
		tc.Vscode.RecordInput == nil || *tc.Vscode.RecordInput {
		t.Errorf("tcpip.vscode = %v", tc.Vscode)
	}
}

func TestRecordingConfigValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml    string
		wantErr string
	}{
		"unknown format": {`
    shell:
      format: mp4
`, "unknown format"},
		"vscode on shell": {`
    shell:
      vscode:
        terminals: true
`, "only valid for directTCPIP"},
		"none on shell": {`
    shell:
      format: none
`, "none is only valid"},
		"none without terminals": {`
    directTCPIP:
      format: none
`, "none is only valid"},
		"none with terminals off": {`
    directTCPIP:
      format: none
      vscode:
        terminals: false
`, "none is only valid"},
		"negative buffer": {`
    bufferBytes: -1
`, "bufferBytes"},
		"pcapng with terminals": {`
    directTCPIP:
      format: pcapng
      vscode:
        terminals: true
`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewConfig(writeConfig(t, tc.yaml))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestRecordingConfigVscodeDefault(t *testing.T) {
	// Without a session service the default stays off: recording would fail the channel.
	cfg, err := NewConfig(writeConfig(t, "    recordShell: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v := cfg.Server.Recording.DirectTCPIP.Vscode; v.Terminals != nil || v.RecordInput != nil {
		t.Errorf("vscode defaults applied without session: %+v", v)
	}

	cfg, err = NewConfig(writeConfigWith(t, "    recordShell: true\n", "session:\n  address: session:9010\n"))
	if err != nil {
		t.Fatal(err)
	}
	v := cfg.Server.Recording.DirectTCPIP.Vscode
	if v.Terminals == nil || !*v.Terminals || v.RecordInput == nil || !*v.RecordInput {
		t.Errorf("vscode defaults not applied: %+v", v)
	}

	cfg, err = NewConfig(writeConfigWith(t, `
    directTCPIP:
      vscode:
        recordInput: false
`, "session:\n  address: session:9010\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v := cfg.Server.Recording.DirectTCPIP.Vscode; *v.RecordInput || !*v.Terminals {
		t.Errorf("configured recordInput must win over the default: %+v", v)
	}
}

func TestTcpipRecording(t *testing.T) {
	none := sessionv1.RecordingFormat_RECORDING_FORMAT_NONE
	unspecified := sessionv1.RecordingFormat_RECORDING_FORMAT_UNSPECIFIED
	pcapng := sessionv1.RecordingFormat_RECORDING_FORMAT_PCAPNG
	vscodeOn := StreamRecordingOptions{Vscode: VscodeRecordingOptions{Terminals: boolPtr(true), RecordInput: boolPtr(true)}}

	for name, tc := range map[string]struct {
		cfg       RecordingConfig
		ob        *authz.RecordObligation
		record    bool
		format    sessionv1.RecordingFormat
		terminals bool
		input     bool
	}{
		"config off":               {cfg: RecordingConfig{}, record: false},
		"config raw only":          {cfg: RecordingConfig{RecordDirectTCPIP: true}, record: true, format: unspecified},
		"config vscode only":       {cfg: RecordingConfig{DirectTCPIP: vscodeOn}, record: true, format: none, terminals: true, input: true},
		"config raw and vscode":    {cfg: RecordingConfig{RecordDirectTCPIP: true, DirectTCPIP: vscodeOn}, record: true, format: unspecified, terminals: true, input: true},
		"obligation off":           {cfg: RecordingConfig{RecordDirectTCPIP: true, DirectTCPIP: vscodeOn}, ob: &authz.RecordObligation{Shell: true}, record: false},
		"obligation vscode only":   {cfg: RecordingConfig{RecordDirectTCPIP: true}, ob: &authz.RecordObligation{VscodeTerminals: true}, record: true, format: none, terminals: true},
		"obligation raw no vscode": {cfg: RecordingConfig{DirectTCPIP: vscodeOn}, ob: &authz.RecordObligation{DirectTCPIP: true}, record: true, format: unspecified},
		"obligation raw overrides config none": {
			cfg:    RecordingConfig{DirectTCPIP: StreamRecordingOptions{Format: "none", Vscode: vscodeOn.Vscode}},
			ob:     &authz.RecordObligation{DirectTCPIP: true, VscodeTerminals: true, VscodeInput: true},
			record: true, format: unspecified, terminals: true, input: true,
		},
		"obligation keeps configured format": {
			cfg:    RecordingConfig{DirectTCPIP: StreamRecordingOptions{Format: "pcapng"}},
			ob:     &authz.RecordObligation{DirectTCPIP: true},
			record: true, format: pcapng,
		},
	} {
		t.Run(name, func(t *testing.T) {
			record, opts := tc.cfg.tcpipRecording(tc.ob)
			if record != tc.record {
				t.Fatalf("record = %v, want %v", record, tc.record)
			}
			if !record {
				return
			}
			if opts.Format != tc.format {
				t.Errorf("format = %v, want %v", opts.Format, tc.format)
			}
			if got := opts.GetVscode().GetTerminals(); got != tc.terminals {
				t.Errorf("terminals = %v, want %v", got, tc.terminals)
			}
			if got := opts.GetVscode().GetRecordInput(); got != tc.input {
				t.Errorf("recordInput = %v, want %v", got, tc.input)
			}
		})
	}

	// The shared config must not be mutated by a per-channel decision.
	cfg := RecordingConfig{DirectTCPIP: StreamRecordingOptions{Format: "none", Vscode: vscodeOn.Vscode}}
	cfg.tcpipRecording(&authz.RecordObligation{DirectTCPIP: true})
	if cfg.DirectTCPIP.Format != "none" || !*cfg.DirectTCPIP.Vscode.Terminals {
		t.Errorf("config mutated: %+v", cfg.DirectTCPIP)
	}
}
