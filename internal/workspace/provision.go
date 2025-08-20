package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/k8shell-io/identity/pkg/userstr"
	provisionerClient "github.com/k8shell-io/provisioner/pkg/client"
	provisionerModels "github.com/k8shell-io/provisioner/pkg/models"
)

// EnsureWorkspace checks if a workspace exists for the user and provisions it if not.
func EnsureWorkspace(ctx context.Context, userStr *userstr.UserStr, writer io.Writer,
	provisioner *provisionerClient.Client) (*provisionerModels.WorkspaceStatus, error) {

	workspaces, err := provisioner.GetWorkspaces(ctx, userStr.User, userStr.Blueprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", userStr.User, err)
	}

	if len(workspaces) > 0 {
		status, err := provisioner.GetWorkspaceStatus(ctx, workspaces[0].Name)
		if err != nil {
			if !errors.Is(err, provisionerModels.ErrWorkspaceNotFound) {
				return nil, fmt.Errorf("failed to get workspace status for user %s: %w", userStr.User, err)
			}
		} else {
			if status.Status == "Running" {
				return status, nil
			}
		}
	}

	name, err := provisionWorkspace(ctx, userStr, writer, provisioner)
	if err != nil {
		return nil, fmt.Errorf("failed to provision workspace for user %s: %w", userStr.User, err)
	}

	status, err := provisioner.GetWorkspaceStatus(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", userStr.User, err)
	}
	if status.Status == "Running" {
		return status, nil
	}

	return nil, fmt.Errorf("failed to ensure workspace for user %s: workspace status is %q",
		userStr.User, status.Status)
}

// provisionWorkspace provisions a new workspace for the user.
func provisionWorkspace(ctx context.Context, userStr *userstr.UserStr, writer io.Writer,
	provisioner *provisionerClient.Client) (string, error) {
	events := make(chan provisionerModels.StreamEvent, 100)
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

		provisionErr = provisioner.ProvisionWorkspaceStream(ctx, &provisionerClient.ProvisionOptions{
			Username:  userStr.User,
			Blueprint: userStr.Blueprint,
			Timeout:   30,
			Stream:    true,
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
