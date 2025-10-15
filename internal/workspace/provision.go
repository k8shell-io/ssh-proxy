// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package workspace

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
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

// InfoWriterOptions defines options for the InfoWriter.
type InfoWriterOptions struct {
	ShowProvisionInfo bool `yaml:"showProvisionInfo"`
	ShowPulse         bool `yaml:"showPulse"`
	ShowPercentage    bool `yaml:"showPercentage"`
	ShowErrors        bool `yaml:"showErrors"`
	ShowSystemErrors  bool `yaml:"showSystemErrors"`
	TotalEvents       int  `yaml:"totalEvents"`
}

// InfoWriter writes information to the channel during provisioning.
type InfoWriter struct {
	io.Writer
	otps          *InfoWriterOptions
	progress      int
	provStarted   bool
	pulseProgress int          // Add this for pulse animation
	pulseTicker   *time.Ticker // Add this for pulse timer
	pulseStop     chan bool    // Add this to stop pulse animation
	pulseMutex    sync.Mutex   // Add this to protect pulse updates
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
			TotalEvents:       12,
		}
	}
	if opts.TotalEvents == 0 {
		opts.TotalEvents = 12
	}
	return &InfoWriter{
		Writer:    w,
		otps:      opts,
		progress:  0,
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
				perc := min((w.progress*100)/w.otps.TotalEvents, 100)
				if perc < 100 {
					w.drawPulseAndPercentage(perc)
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

	if w.otps.ShowPulse {
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

	if w.otps.ShowPercentage {
		output.WriteString(fmt.Sprintf(" %d%%", percentage))
	}

	fmt.Fprint(w.Writer, output.String())
}

// WriteEvent writes a provisioning event to the channel
func (w *InfoWriter) WriteEvent(p string) {
	if w.Writer == nil {
		return
	}
	if w.otps.ShowProvisionInfo {
		w.Writer.Write([]byte(p + "\r\n"))
	} else {
		w.pulseMutex.Lock()
		w.progress++
		perc := min((w.progress*100)/w.otps.TotalEvents, 100)
		w.drawPulseAndPercentage(perc)
		w.pulseMutex.Unlock()
	}
}

// WriteMessage writes a general message to the channel
func (w *InfoWriter) WriteMessage(p string) {
	if w.Writer == nil {
		return
	}
	fmt.Fprintf(w.Writer, "%s\r\n", p)
}

// WriteError writes an error message to the channel if enabled
func (w *InfoWriter) WriteError(p string) {
	if w.Writer != nil && w.otps.ShowErrors {
		fmt.Fprintf(w.Writer, "%s\r\n", p)
	}
}

// WriteSystemError writes a system error message to the channel if enabled
func (w *InfoWriter) WriteSystemError(p string) {
	if w.Writer != nil && w.otps.ShowSystemErrors {
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
	if w.otps.ShowProvisionInfo {
		w.Writer.Write([]byte("Starting workspace...\r\n"))
	} else if w.otps.ShowPulse || w.otps.ShowPercentage {
		w.progress = 0
		w.drawPulseAndPercentage(0)
		if w.otps.ShowPulse {
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
	if w.provStarted {
		w.stopPulseAnimation()
		w.drawPulseAndPercentage(100, hasError)
		fmt.Fprintf(w.Writer, "\r\n")
	}
}

// EnsureWorkspace checks if a workspace exists for the user and provisions it if not.
func EnsureWorkspace(ctx context.Context, userStr *models.UserStr, writer *InfoWriter,
	client *provisioner.Client) (*models.WorkspaceStatus, string, error) {

	// find the workspace for the user and blueprint
	workspacepb, err := client.GetUserWorkspaceInfo(ctx, &provisionerpb.GetUserWorkspacesRequest{
		Username:  userStr.Username,
		Blueprint: userStr.Blueprint,
	})
	if err != nil {
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.NotFound {
			return nil, "", fmt.Errorf("failed to get workspace for user %s: %w", userStr.Username, err)
		}
	}

	if workspacepb != nil {
		status, err := client.GetWorkspaceStatus(ctx, &provisionerpb.Workspace{Workspace: workspacepb.Name})
		if err != nil {
			return nil, "", fmt.Errorf("failed to get workspace status for user %s: %w", userStr.Username, err)
		}
		if status.GetPodStatus().Status == "Running" {
			return gapi.ProtoToWorkspaceStatus(status), workspacepb.GetAppVersion(), nil
		}
	}

	wsname, err := provisionWorkspace(ctx, userStr, writer, client)
	if err != nil {
		return nil, "", fmt.Errorf("failed to provision workspace for user %s: %w", userStr.Username, err)
	}

	status, err := client.GetWorkspaceStatus(ctx, &provisionerpb.Workspace{Workspace: wsname})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get workspace status for user %s: %w", userStr.Username, err)
	}

	fmt.Printf("***** Workspace status after provisioning: version=%s, status=%v\n",
		status.GetAppVersion(), status.GetPodStatus())

	if status.GetPodStatus().Status == "Running" {
		return gapi.ProtoToWorkspaceStatus(status), status.GetAppVersion(), nil
	}

	return nil, "", fmt.Errorf("failed to ensure workspace for user %s: workspace status is %q",
		userStr.Username, status.GetPodStatus().Status)
}

// provisionWorkspace provisions a new workspace for the user.
func provisionWorkspace(ctx context.Context, userStr *models.UserStr, writer *InfoWriter,
	client *provisioner.Client) (string, error) {
	var (
		name     string
		eventErr error
	)

	writer.StartProvisioning()
	defer func() {
		writer.EndProvisioning(eventErr != nil)
	}()

	stream, err := client.ProvisionWorkspaceStream(ctx, &provisionerpb.ProvisionWorkspaceRequest{
		Userstr: userStr.Raw,
		Timeout: 30,
	})
	if err != nil {
		eventErr = fmt.Errorf("failed to create provision stream: %w", err)
		return "", eventErr
	}

loop:
	for {
		select {
		case <-ctx.Done():
			eventErr = ctx.Err()
			break loop

		default:
			event, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					break loop
				}
				eventErr = fmt.Errorf("stream error: %w", err)
				break loop
			}

			streamEvent := models.WorkspaceStreamEvent{
				Type:       event.GetType(),
				Status:     event.GetStatus(),
				Message:    event.GetMessage(),
				ObjectName: event.GetObjectName(),
				Timestamp:  event.GetTimestamp(),
			}

			writer.WriteEvent(streamEvent.String())

			switch streamEvent.Status {
			case "Running":
				name = streamEvent.ObjectName
				break loop

			case "Error":
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
