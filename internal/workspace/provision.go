package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"

	provisionerClient "github.com/k8shell-io/provisioner/pkg/client"
	provisionerModels "github.com/k8shell-io/provisioner/pkg/models"
)

// EnsureWorkspace checks if a workspace exists for the user and provisions it if not.
func EnsureWorkspace(ctx context.Context, username string, blueprint string, writer io.Writer,
	provisioner *provisionerClient.Client) (*provisionerModels.WorkspaceStatus, error) {

	workspaces, err := provisioner.GetWorkspaces(ctx, username, blueprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", username, err)
	}

	if len(workspaces) > 0 {
		status, err := provisioner.GetWorkspaceStatus(ctx, workspaces[0].Name)
		if err != nil {
			if !errors.Is(err, provisionerModels.ErrWorkspaceNotFound) {
				return nil, fmt.Errorf("failed to get workspace status for user %s: %w", username, err)
			}
		} else {
			if status.Status == "Running" {
				return status, nil
			}
		}
	}

	name, err := provisionWorkspace(ctx, username, blueprint, writer, provisioner)
	if err != nil {
		return nil, fmt.Errorf("failed to provision workspace for user %s: %w", username, err)
	}

	status, err := provisioner.GetWorkspaceStatus(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace status for user %s: %w", username, err)
	}
	if status.Status == "Running" {
		return status, nil
	}

	return nil, fmt.Errorf("failed to ensure workspace for user %s: workspace status is %q",
		username, status.Status)
}

// provisionWorkspace provisions a new workspace for the user.
func provisionWorkspace(ctx context.Context, username string, blueprint string, writer io.Writer,
	provisioner *provisionerClient.Client) (string, error) {
	events := make(chan provisionerModels.StreamEvent, 100)
	if writer != nil {
		writer.Write([]byte("Provisioning workspace...\r\n"))
	}
	var name string
	var err error

	provisioningDone := make(chan bool, 1)

	go func() {
		err = provisioner.ProvisionWorkspaceStream(ctx, &provisionerClient.ProvisionOptions{
			Username:  username,
			Blueprint: blueprint,
			Timeout:   30,
			Stream:    true,
		}, events)
		provisioningDone <- true
	}()

	go func() {
		defer func() { provisioningDone <- true }()

		for event := range events {
			if writer != nil {
				writer.Write([]byte(fmt.Sprintf("%s\r\n", event.String())))
			}

			if event.Status == "Running" {
				name = event.ObjectName
			}

			if event.Status == "Error" {
				err = fmt.Errorf("provisioning error: %s", event.Message)
			}
		}
	}()

	<-provisioningDone
	return name, err
}
