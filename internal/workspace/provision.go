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

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	identity "github.com/k8shell-io/identity/pkg/api"
	provisioner "github.com/k8shell-io/provisioner/pkg/api"
	"github.com/k8shell-io/provisioner/pkg/api/provisionerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ProvisionError represents an error that occurred during provisioning.
type ProvisionError struct {
	Message string
}

// Error returns the error message.
func (e *ProvisionError) Error() string {
	return e.Message
}

// Backends defines an interface for accessing backend services.
type Backends interface {
	Provisioner() *provisioner.Client
	Identity() *identity.Client
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
					w.drawPulseAndPercentage(w.perc)
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
func (w *InfoWriter) drawPulseAndPercentage(percentage int, hasError ...bool) {
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

	output.WriteString("Starting workspace...")

	if w.opts.ShowPercentage {
		output.WriteString(fmt.Sprintf(" %d%%", percentage))
	}

	fmt.Fprint(w.Writer, output.String())
}

// WriteEvent writes a provisioning event to the channel
func (w *InfoWriter) WriteEvent(event models.WorkspaceStreamEvent) {
	if w.Writer == nil {
		return
	}
	if w.opts.ShowProvisionInfo && (event.Type == "event" || event.Type == "status") {
		_, _ = w.Writer.Write([]byte(event.String() + "\r\n"))
	} else if (w.opts.ShowPulse || w.opts.ShowPercentage) && event.Type == "progress" {
		w.pulseMutex.Lock()
		perc, _ := strconv.Atoi(string(event.Status))
		w.perc = perc
		w.drawPulseAndPercentage(w.perc)
		w.pulseMutex.Unlock()
	}
}

// WriteMessage writes a general message to the channel
func (w *InfoWriter) WriteMessage(p string) {
	if w.Writer == nil {
		return
	}
	_, _ = fmt.Fprintf(w.Writer, "%s\r\n", p)
}

// WriteError writes an error message to the channel if enabled
func (w *InfoWriter) WriteError(p string) {
	if w.Writer != nil && w.opts.ShowErrors {
		fmt.Fprintf(w.Writer, "%s\r\n", p)
	}
}

// WriteSystemError writes a system error message to the channel if enabled
func (w *InfoWriter) WriteSystemError(p string) {
	if w.Writer != nil && w.opts.ShowSystemErrors {
		fmt.Fprintf(w.Writer, "%s\r\n", p)
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
		w.drawPulseAndPercentage(0)
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
		w.drawPulseAndPercentage(100, hasError)
		fmt.Fprintf(w.Writer, "\r\n")
	}
}

// EnsureWorkspace checks if a workspace exists for the user and provisions it if not.
func EnsureWorkspace(ctx context.Context, userStr *models.UserStr, writer *InfoWriter,
	backends Backends) (*models.WorkspaceDetails, error) {

	canUserStr, err := userStr.Canonicalize()
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize user string for user %s: %w", userStr.Username, err)
	}

	wsStatus, err := backends.Provisioner().FindWorkspace(ctx,
		&provisionerpb.FindWorkspaceRequest{Workspace: canUserStr.WorkspaceName})
	if err != nil {
		if status.Code(err) != codes.NotFound {
			return nil, fmt.Errorf("failed to get workspace status for user %s: %w", userStr.Username, err)
		}
	} else {
		if wsStatus.GetPodStatus().Status == "Running" {
			return gapi.ProtoToWorkspaceDetails(wsStatus), nil
		}
	}

	wsname, err := provisionWorkspace(ctx, canUserStr.CanonicalUserStrObj, writer, backends)
	if err != nil {
		return nil, fmt.Errorf("failed to provision workspace for user %s: %w", userStr.Username, err)
	}

	wsStatus, err = backends.Provisioner().FindWorkspace(ctx,
		&provisionerpb.FindWorkspaceRequest{Workspace: wsname})
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", userStr.Username, err)
	}

	if wsStatus.GetPodStatus().Status == "Running" {
		return gapi.ProtoToWorkspaceDetails(wsStatus), nil
	}

	return nil, fmt.Errorf("failed to ensure workspace for user %s: workspace status is %q",
		userStr.Username, wsStatus.GetPodStatus().Status)
}

// provisionWorkspace provisions a new workspace for the user.
func provisionWorkspace(ctx context.Context, userStr *models.UserStr, writer *InfoWriter,
	backends Backends) (string, error) {
	var (
		name     string
		eventErr error
	)

	writer.StartProvisioning()
	defer func() {
		writer.EndProvisioning(eventErr != nil)
	}()

	_, _, stream, err := backends.Provisioner().ProvisionHandshake(ctx, *userStr, 20)
	if err != nil {
		return "", fmt.Errorf("handshake failed for user %s: %w", userStr.Username, err)
	}

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
				Status:     models.WorkspacePodStatus(event.Status),
				Message:    event.Message,
				ObjectName: event.ObjectName,
				Timestamp:  event.Timestamp,
			}
			writer.WriteEvent(streamEvent)

			switch streamEvent.Status {
			case models.WorkspaceStatusRunning:
				name = streamEvent.ObjectName
				break loop

			case models.WorkspaceStatusFailing, models.WorkspaceStatusStopped:
				eventErr = fmt.Errorf("%s", streamEvent.Message)
				break loop
			}
		}
	}

	if eventErr != nil {
		return "", &ProvisionError{Message: eventErr.Error()}
	}
	if name == "" {
		return "", fmt.Errorf("provisioning completed but no running workspace name received")
	}

	return name, nil
}
