// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package workspace

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k8shell-io/common/pkg/api/client/identity"
	"github.com/k8shell-io/common/pkg/api/client/provisioner"
	provisionerv1 "github.com/k8shell-io/common/pkg/api/gen/go/provisioner/v1"
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/userstr"
	"google.golang.org/grpc"
)

const PROVISION_TIMEOUT = 120 * time.Second

// ProvisionError represents an error that occurred during provisioning.
// type ProvisionError struct {
// 	Message string
// }

// Error returns the error message.
// func (e *ProvisionError) Error() string {
// 	return e.Message
// }

var ErrProvisionFailed = fmt.Errorf("workspace provisioning failed")
var ErrWorkspaceNotFound = fmt.Errorf("workspace not found")

// Backends defines an interface for accessing backend services.
type Backends interface {
	Provisioner() *provisioner.Client
	Identity() *identity.IdentityClient
}

// InfoWriterOptions defines options for the InfoWriter.
type InfoWriterOptions struct {
	ShowProvisionInfo bool `yaml:"showProvisionInfo"`
	ShowPulse         bool `yaml:"showPulse"`
	ShowPercentage    bool `yaml:"showPercentage"`
	ShowErrors        bool `yaml:"showErrors"`
	ShowSystemErrors  bool `yaml:"showSystemErrors"`
}

// InfoWriter writes information to the channel during provisioning.
type InfoWriter struct {
	io.Writer
	opts          *InfoWriterOptions
	provStarted   bool
	pulseProgress int          // pulse animation
	pulseTicker   *time.Ticker // pulse timer
	pulseStop     chan bool    // stop pulse animation
	pulseMutex    sync.Mutex   // protect pulse updates
	perc          int
	extraMessage  string
}

// NewInfoWriter creates a new InfoWriter with the given options.
func NewInfoWriter(w io.Writer, opts *InfoWriterOptions) *InfoWriter {
	if opts == nil {
		opts = &InfoWriterOptions{
			ShowProvisionInfo: false,
			ShowPulse:         false,
			ShowPercentage:    false,
			ShowErrors:        false,
			ShowSystemErrors:  false,
		}
	} else {
		if opts.ShowPulse && opts.ShowProvisionInfo {
			opts.ShowPulse = false
		}
		if !opts.ShowPulse {
			opts.ShowPercentage = false
		}
	}
	return &InfoWriter{
		Writer:    w,
		opts:      opts,
		pulseStop: make(chan bool, 1),
	}
}

// startPulseAnimation starts the pulse animation timer
func (w *InfoWriter) startPulseAnimation() {
	if w.pulseTicker != nil {
		return
	}

	w.pulseTicker = time.NewTicker(100 * time.Millisecond)
	go func() {
		for {
			select {
			case <-w.pulseTicker.C:
				w.pulseMutex.Lock()
				w.pulseProgress++
				if w.perc < 100 {
					w.drawPulseAndPercentage(w.perc, w.extraMessage)
				}
				w.pulseMutex.Unlock()
			case <-w.pulseStop:
				return
			}
		}
	}()
}

// stopPulseAnimation stops the pulse animation timer
func (w *InfoWriter) stopPulseAnimation() {
	if w.pulseTicker != nil {
		w.pulseTicker.Stop()
		w.pulseTicker = nil
		select {
		case w.pulseStop <- true:
		default:
		}
	}
}

// drawPulseAndPercentage draws pulse and/or percentage based on options
func (w *InfoWriter) drawPulseAndPercentage(percentage int, extraMessage string, hasError ...bool) {
	if w.Writer == nil {
		return
	}

	var output strings.Builder
	output.WriteString("\r")

	if w.opts.ShowPulse {
		if percentage < 100 {
			pulseChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			pulseIndex := w.pulseProgress % len(pulseChars)
			output.WriteString(pulseChars[pulseIndex])
		} else {
			if len(hasError) > 0 && hasError[0] {
				output.WriteString("✗")
			} else {
				output.WriteString("✓")
			}
		}
		output.WriteString(" ")
	}

	baseMessage := "Starting workspace"
	if extraMessage != "" {
		output.WriteString(fmt.Sprintf("%s (%s)...", baseMessage, extraMessage))
	} else {
		output.WriteString(fmt.Sprintf("%s...", baseMessage))
	}

	if w.opts.ShowPercentage && extraMessage == "" {
		output.WriteString(fmt.Sprintf(" %d%%", percentage))
	}

	fmt.Fprint(w.Writer, output.String())
}

// WriteEvent writes a provisioning event to the channel
func (w *InfoWriter) WriteEvent(event models.WorkspaceStreamEvent) {
	if w.Writer == nil {
		return
	}
	if w.opts.ShowProvisionInfo && (event.Type == models.WorkspaceStreamEventTypeEvent || event.Type == models.WorkspaceStreamEventTypeStatus) {
		_, _ = w.Writer.Write([]byte(event.String() + "\r\n"))
	} else if (w.opts.ShowPulse || w.opts.ShowPercentage) && event.Type == models.WorkspaceStreamEventTypeProgress {
		w.pulseMutex.Lock()
		perc, _ := strconv.Atoi(string(event.Status))
		w.perc = perc
		w.drawPulseAndPercentage(w.perc, w.extraMessage)
		w.pulseMutex.Unlock()
	} else if w.opts.ShowPulse && event.Type == models.WorkspaceStreamEventTypeStatus {
		w.pulseMutex.Lock()
		switch event.Status {
		case models.WorkspaceStatusPulling:
			w.extraMessage = "image pulling"
		case models.WorkspaceStatusProvisioning:
			w.extraMessage = ""
		}
		w.drawPulseAndPercentage(w.perc, w.extraMessage)
		w.pulseMutex.Unlock()
	}
}

// WriteMessage writes a general message to the channel
func (w *InfoWriter) WriteMessage(p string) {
	if w.Writer == nil {
		return
	}
	_, _ = fmt.Fprintf(w.Writer, "%s\r\n", formatClientMessage(p))
}

// WriteError writes an error message to the channel if enabled
func (w *InfoWriter) WriteError(p string) {
	if w.Writer != nil && w.opts.ShowErrors {
		fmt.Fprintf(w.Writer, "%s\r\n", formatClientMessage(p))
	}
}

// WriteSystemError writes a system error message to the channel if enabled
func (w *InfoWriter) WriteSystemError(p string) {
	if w.Writer != nil && w.opts.ShowSystemErrors {
		fmt.Fprintf(w.Writer, "%s\r\n", formatClientMessage(p))
	}
}

// WriteSplash writes a splash message to the channel
func (w *InfoWriter) WriteSplash(splash string) {
	if w.Writer != nil {
		lines := strings.Split(splash, "\n")
		for _, line := range lines {
			fmt.Fprintf(w.Writer, "%s\r\n", line)
		}
	}
}

// StartProvisioning indicates the start of the provisioning process
func (w *InfoWriter) StartProvisioning() {
	if w.Writer == nil {
		return
	}
	if w.opts.ShowProvisionInfo {
		_, _ = w.Writer.Write([]byte("Starting workspace...\r\n"))
	} else if w.opts.ShowPulse || w.opts.ShowPercentage {
		w.perc = 0
		w.extraMessage = ""
		w.drawPulseAndPercentage(0, "")
		if w.opts.ShowPulse {
			w.startPulseAnimation()
		}
	}
	w.provStarted = true
}

// EndProvisioning indicates the end of the provisioning process
func (w *InfoWriter) EndProvisioning(hasError bool) {
	if w.Writer == nil {
		return
	}
	if w.provStarted && (w.opts.ShowPulse || w.opts.ShowPercentage) {
		w.stopPulseAnimation()
		w.drawPulseAndPercentage(100, w.extraMessage, hasError)
		fmt.Fprintf(w.Writer, "\r\n")
	}
}

// EnsureWorkspace checks if a workspace exists for the user and provisions it if not.
func EnsureWorkspace(ctx context.Context, userStr *userstr.UserStr, writer *InfoWriter,
	backends Backends) (*models.WorkspaceDetails, error) {

	canUserStr, err := userStr.Canonicalize()
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize user string for user %s: %w", userStr.Username(), err)
	}

	ws, err := backends.Provisioner().GetWorkspacesByUserStr(ctx,
		&provisionerv1.GetWorkspacesByUserStrRequest{Userstr: canUserStr.CanonicalUserStr()})
	if err != nil {
		return nil, fmt.Errorf("failed to get workspaces for user %s: %w", userStr.Username(), err)
	}
	if len(ws.Workspaces) > 0 {
		for _, wsDetails := range ws.Workspaces {
			if wsDetails.GetWorkspaceStatus().GetStatus() == string(models.WorkspaceStatusRunning) {
				return gapi.ProtoToWorkspaceDetails(wsDetails), nil
			}
		}
		for _, wsDetails := range ws.Workspaces {
			if wsDetails.GetWorkspaceStatus().GetStatus() == string(models.WorkspaceStatusStopped) {
				wsname, err := startWorkspace(ctx, wsDetails.GetName(), writer, backends)
				if err != nil {
					return nil, fmt.Errorf("%w: failed to start workspace", err)
				}
				return finalizeWorkspace(ctx, wsname, userStr.Username(), backends)
			}
		}
		return nil, fmt.Errorf("%w: no running workspaces found. Please try again later.", ErrWorkspaceNotFound)
	}

	if userStr.Pod() != "" {
		return nil, fmt.Errorf("%w: pod=%s, ns=%s", ErrWorkspaceNotFound, userStr.Pod(), userStr.Namespace(""))
	}

	wsname, err := provisionWorkspace(ctx, canUserStr.CanonicalUserStrObj(), writer, backends)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to provision workspace", err)
	}

	return finalizeWorkspace(ctx, wsname, userStr.Username(), backends)
}

// finalizeWorkspace looks up the workspace by name after it has been
// provisioned or resumed and returns its details once confirmed running.
func finalizeWorkspace(ctx context.Context, wsname string, username string, backends Backends) (*models.WorkspaceDetails, error) {
	wsStatus, err := backends.Provisioner().FindWorkspace(ctx,
		&provisionerv1.FindWorkspaceRequest{Workspace: wsname})
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", username, err)
	}

	if wsStatus.GetWorkspaceStatus().GetStatus() == string(models.WorkspaceStatusRunning) {
		return gapi.ProtoToWorkspaceDetails(wsStatus), nil
	}

	return nil, fmt.Errorf("failed to ensure workspace for user %s: workspace status is %q",
		username, wsStatus.GetWorkspaceStatus().GetStatus())
}

// provisionWorkspace provisions a new workspace for the user.
func provisionWorkspace(ctx context.Context, userStr *userstr.UserStr, writer *InfoWriter,
	backends Backends) (string, error) {
	timeout := int32(PROVISION_TIMEOUT / time.Second)
	_, _, stream, err := backends.Provisioner().ProvisionHandshake(ctx, *userStr, timeout)
	if err != nil {
		return "", fmt.Errorf("handshake failed for user %s: %w", userStr.Username(), err)
	}

	return consumeProvisionStream(ctx, stream, writer)
}

// startWorkspace resumes a previously stopped workspace.
func startWorkspace(ctx context.Context, workspaceName string, writer *InfoWriter,
	backends Backends) (string, error) {
	timeout := int32(PROVISION_TIMEOUT / time.Second)
	_, _, stream, err := backends.Provisioner().StartHandshake(ctx, workspaceName, timeout)
	if err != nil {
		return "", fmt.Errorf("start handshake failed for workspace %s: %w", workspaceName, err)
	}

	return consumeProvisionStream(ctx, stream, writer)
}

// consumeProvisionStream drains a provisioning/start stream, reporting
// progress via writer, until the workspace reaches a terminal state.
func consumeProvisionStream(ctx context.Context,
	stream grpc.ServerStreamingClient[provisionerv1.ProvisionWorkspaceResponse], writer *InfoWriter) (string, error) {
	var (
		name     string
		eventErr error
	)

	writer.StartProvisioning()
	defer func() {
		writer.EndProvisioning(eventErr != nil)
	}()

loop:
	for {
		select {
		case <-ctx.Done():
			eventErr = ctx.Err()
			break loop

		default:
			msg, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					break loop
				}
				eventErr = fmt.Errorf("stream error: %w", err)
				break loop
			}
			event := msg.GetEvent()
			if event == nil {
				eventErr = fmt.Errorf("invalid stream message: expected event, got %+v", msg)
				break loop
			}

			streamEvent := models.WorkspaceStreamEvent{
				Type:       models.WorkspaceStreamEventType(event.Type),
				Status:     models.WorkspaceStatusMessage(event.Status),
				Message:    event.Message,
				ObjectName: event.ObjectName,
				Timestamp:  event.Timestamp,
			}
			writer.WriteEvent(streamEvent)

			switch streamEvent.Status {
			case models.WorkspaceStatusRunning:
				name = streamEvent.ObjectName
				break loop

			case models.WorkspaceStatusFailing, models.WorkspaceStatusStopped, models.WorkspaceStatusError:
				eventErr = fmt.Errorf("%s", streamEvent.Message)
				break loop
			}
		}
	}

	if eventErr != nil {
		return "", fmt.Errorf("%w: provisioning failed: %s", ErrProvisionFailed, eventErr.Error())
	}
	if name == "" {
		return "", fmt.Errorf("provisioning completed but no running workspace name received")
	}

	return name, nil
}

// formatClientMessage formats an error message by removing newlines and extra spaces
func formatClientMessage(err string) string {
	msg := err
	msg = strings.NewReplacer("\r", " ", "\n", " ").Replace(msg)
	return strings.Join(strings.Fields(msg), " ")
}
