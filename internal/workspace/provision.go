package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/k8shell-io/common/models"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	provModels "github.com/k8shell-io/provisioner/pkg/models"
)

// EnsureWorkspace checks if a workspace exists for the user and provisions it if not.
func EnsureWorkspace(ctx context.Context, userStr *models.UserStr, writer io.Writer,
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
func provisionWorkspace(ctx context.Context, userStr *models.UserStr, writer io.Writer,
	client *provisioner.Client) (string, error) {
	events := make(chan provModels.StreamEvent, 100)
	if writer != nil {
		writer.Write([]byte("Provisioning workspace...\r\n"))
	}

	var name string
	var provisionErr error
	var eventErr error

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(events)

		provisionErr = client.ProvisionWorkspaceStream(ctx, &provisioner.ProvisionOptions{
			UserStr: *userStr,
			Timeout: 30,
			Stream:  true,
		}, events)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for event := range events {
			if writer != nil {
				writer.Write([]byte(fmt.Sprintf("%s\r\n", event.String())))
			}

			if event.Status == "Running" {
				name = event.ObjectName
			}

			if event.Status == "Error" {
				eventErr = fmt.Errorf("provisioning error: %s", event.Message)
			}
		}
	}()

	wg.Wait()

	if eventErr != nil {
		return "", eventErr
	}
	if provisionErr != nil {
		return "", provisionErr
	}
	if name == "" {
		return "", fmt.Errorf("provisioning completed but no running workspace name received")
	}

	return name, nil
}
