package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/k8shell-io/common/models"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	provModels "github.com/k8shell-io/provisioner/pkg/models"
)

type ProvisionError struct {
	Message string
}

func (e *ProvisionError) Error() string {
	return e.Message
}

type InfoWriterOptions struct {
	ShowProvisionInfo bool `yaml:"showProvisionInfo"`
	ShowPulse         bool `yaml:"showPulse"`
	ShowPercentage    bool `yaml:"showPercentage"`
	ShowErrors        bool `yaml:"showErrors"`
	ShowSystemErrors  bool `yaml:"showSystemErrors"`
	TotalEvents       int  `yaml:"totalEvents"`
}

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

func (w *InfoWriter) WriteMessage(p string) {
	if w.Writer == nil {
		return
	}
	fmt.Fprintf(w.Writer, "%s\r\n", p)
}

func (w *InfoWriter) WriteError(p string) {
	if w.Writer != nil && w.otps.ShowErrors {
		fmt.Fprintf(w.Writer, "%s\r\n", p)
	}
}

func (w *InfoWriter) WriteSystemError(p string) {
	if w.Writer != nil && w.otps.ShowSystemErrors {
		fmt.Fprintf(w.Writer, "%s\r\n", p)
	}
}

func (w *InfoWriter) WriteSplash(splash string) {
	if w.Writer != nil {
		lines := strings.Split(splash, "\n")
		for _, line := range lines {
			fmt.Fprintf(w.Writer, "%s\r\n", line)
		}
	}
}

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
	client *provisioner.Client) (*provModels.WorkspaceStatus, error) {

	workspaces, err := client.GetWorkspaces(ctx, userStr.Username, userStr.Blueprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", userStr.Username, err)
	}

	if len(workspaces) > 0 {
		status, err := client.GetWorkspaceStatus(ctx, workspaces[0].Name)
		if err != nil {
			if !errors.Is(err, provModels.ErrWorkspaceNotFound) {
				return nil, fmt.Errorf("failed to get workspace status for user %s: %w", userStr.Username, err)
			}
		} else {
			if status.Status == "Running" {
				return status, nil
			}
		}
	}

	name, err := provisionWorkspace(ctx, userStr, writer, client)
	if err != nil {
		return nil, fmt.Errorf("failed to provision workspace for user %s: %w", userStr.Username, err)
	}

	status, err := client.GetWorkspaceStatus(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", userStr.Username, err)
	}
	if status.Status == "Running" {
		return status, nil
	}

	return nil, fmt.Errorf("failed to ensure workspace for user %s: workspace status is %q",
		userStr.Username, status.Status)
}

// provisionWorkspace provisions a new workspace for the user.
func provisionWorkspace(ctx context.Context, userStr *models.UserStr, writer *InfoWriter,
	client *provisioner.Client) (string, error) {
	events := make(chan provModels.StreamEvent, 100)

	var name string
	var provisionErr error
	var eventErr error
	var systemErr error

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(events)

		select {
		case <-ctx.Done():
			systemErr = ctx.Err()
			return
		default:
			provisionErr = client.ProvisionWorkspaceStream(ctx, &provisioner.ProvisionOptions{
				UserStr: *userStr,
				Timeout: 30,
				Stream:  true,
			}, events)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for event := range events {
			if event.Type == "status" && event.Status == "Starting" {
				writer.StartProvisioning()
				continue
			}
			writer.WriteEvent(event.String())

			if event.Status == "Running" {
				name = event.ObjectName
			}

			if event.Status == "Error" {
				eventErr = fmt.Errorf("%s", event.Message)
			}
		}
		hasError := eventErr != nil || provisionErr != nil || systemErr != nil
		writer.EndProvisioning(hasError)
	}()

	wg.Wait()

	if systemErr != nil {
		return "", systemErr
	}
	if eventErr != nil {
		return "", &ProvisionError{Message: eventErr.Error()}
	}
	if provisionErr != nil {
		return "", &ProvisionError{Message: provisionErr.Error()}
	}
	if name == "" {
		return "", fmt.Errorf("provisioning completed but no running workspace name received")
	}

	return name, nil
}
