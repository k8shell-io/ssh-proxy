// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package workspace

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/common/pkg/models"
	pb "github.com/k8shell-io/k8shelld/pkg/api/k8shelldpb"
	"github.com/rs/zerolog"

	"github.com/k8shell-io/k8shelld/pkg/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// K8shelld_v11 is a client for interacting with the k8shelld gRPC service.
type K8shelld_v11 struct {
	conn             *grpc.ClientConn
	log              *zerolog.Logger
	systemClient     pb.SystemServiceClient
	shellClient      pb.ShellServiceClient
	execClient       pb.ExecServiceClient
	pfClient         pb.PortForwardServiceClient
	unixSocketClient pb.UnixSocketServiceClient
	AccessKey        string
	counters         *api.ConnCounters
	TLSCert          string
	Host             string
	Address          string
	Port             int
}

func NewK8shelld_v11(status *models.WorkspaceStatus, counters *api.ConnCounters) (K8shelldClient, error) {
	c := &K8shelld_v11{
		log:       log.NewLogger("k8shelld.client"),
		counters:  counters,
		AccessKey: status.AccessKey,
		TLSCert:   status.TLSCert,
		Host:      status.Host,
		Address:   status.PodIP,
		Port:      status.Port,
	}

	var creds credentials.TransportCredentials
	if c.TLSCert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.TLSCert)) {
			return nil, fmt.Errorf("failed to append TLS certificate to pool")
		}
		creds = credentials.NewTLS(&tls.Config{
			ServerName: c.Host,
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		})
	} else {
		creds = credentials.NewTLS(&tls.Config{
			ServerName:         c.Host,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                KEEPALIVE_TIME,
			Timeout:             KEEPALIVE_TIMEOUT,
			PermitWithoutStream: true,
		}),
		grpc.WithAuthority(c.Host),
	}

	var err error
	target := fmt.Sprintf("%s:%d", c.Address, c.Port)
	c.conn, err = grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	c.systemClient = pb.NewSystemServiceClient(c.conn)
	c.shellClient = pb.NewShellServiceClient(c.conn)
	c.execClient = pb.NewExecServiceClient(c.conn)
	c.pfClient = pb.NewPortForwardServiceClient(c.conn)
	c.unixSocketClient = pb.NewUnixSocketServiceClient(c.conn)

	return c, nil
}

// Close closes the gRPC connection.
func (c *K8shelld_v11) Close() error {
	return c.conn.Close()
}

// EnsureWorkspace ensures that a workspace is provisioned and running for the user.
func (c *K8shelld_v11) RunCommandProcessor(ctx context.Context, handler api.CommandHandler) error {
	return fmt.Errorf("RunCommandProcessor is not implemented in k8shelld v0.11 client")
}

// Handshake performs a handshake with the k8shelld service to establish a session.
func (c *K8shelld_v11) Handshake(ctx context.Context, user *models.User, envVars []string) (*pb.HandshakeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	md := metadata.Pairs("authorization", c.AccessKey)
	ctx = metadata.NewOutgoingContext(ctx, md)

	req := &pb.HandshakeRequest{
		User: &pb.User{
			Username:  user.Username,
			Uid:       user.UID,
			Gid:       user.GID,
			UserToken: user.AccessToken,
		},
		EnvVars: envVars,
	}

	return c.systemClient.Handshake(ctx, req)
}

// RunShell creates a PTY shell session over gRPC and bridges it with the SSH channel.
func (c *K8shelld_v11) RunShell(ctx context.Context, upstream api.BufferedReadWriter,
	sessionId string, envVars []string,
	width, height uint32, usePty bool) error {
	md := metadata.Pairs(
		"authorization", c.AccessKey,
		"session-id", sessionId,
	)
	ctx = metadata.NewOutgoingContext(ctx, md)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.shellClient.Shell(ctx)
	if err != nil {
		return fmt.Errorf("failed to create shell stream: %w", err)
	}

	startReq := &pb.ShellRequest{
		Request: &pb.ShellRequest_StartRequest{
			StartRequest: &pb.ShellStartRequest{
				CmdShell:   "/bin/sh",
				SetEnvVars: envVars,
				UsePty:     usePty,
				Width:      width,
				Height:     height,
			},
		},
	}
	if err := stream.Send(startReq); err != nil {
		return fmt.Errorf("failed to send start request: %w", err)
	}

	errCh := make(chan error, 2)

	// writer goroutine (SSH -> gRPC)
	go func() {
		defer func() { _ = stream.CloseSend() }()

		buf := make([]byte, 32*1024)
		for {
			n, rerr := upstream.Read(buf)
			if rerr != nil {
				if rerr == io.EOF {
					errCh <- nil
				} else {
					errCh <- fmt.Errorf("ssh read: %w", rerr)
				}
				return
			}
			if n == 0 {
				continue
			}
			if serr := stream.Send(&pb.ShellRequest{
				Request: &pb.ShellRequest_Data{
					Data: buf[:n],
				},
			}); serr != nil {
				errCh <- fmt.Errorf("grpc send: %w", serr)
				return
			}
			c.counters.AddIn(n)
		}
	}()

	// reader goroutine (gRPC -> SSH)
	go func() {
		for {
			resp, rerr := stream.Recv()
			if rerr != nil {
				if rerr == io.EOF {
					errCh <- nil
				} else {
					errCh <- fmt.Errorf("grpc recv: %w", rerr)
				}
				return
			}

			switch r := resp.Response.(type) {
			case *pb.ShellResponse_Data:
				if _, werr := upstream.Write(r.Data); werr != nil {
					errCh <- fmt.Errorf("ssh write: %w", werr)
					return
				}
				c.counters.AddOut(len(r.Data))
			case *pb.ShellResponse_Terminate:
				if r.Terminate {
					errCh <- nil
					return
				}
			}
		}
	}()

	err = <-errCh

	// Drain the second result
	select {
	case <-errCh:
	default:
	}

	return err
}

// ResizeTerminal resizes the terminal
func (c *K8shelld_v11) ResizeTerminal(ctx context.Context, sessionId string, width, height uint32) error {
	md := metadata.Pairs("authorization", c.AccessKey, "session-id", sessionId)
	ctx = metadata.NewOutgoingContext(ctx, md)

	req := &pb.ResizeTerminalRequest{
		Width:  width,
		Height: height,
	}

	_, err := c.shellClient.ResizeTerminal(ctx, req)
	return err
}

// RunUnixSocket creates a Unix socket connection over gRPC and bridges it with the SSH channel.
func (c *K8shelld_v11) RunUnixSocket(ctx context.Context, upstream api.BufferedReadWriter,
	unixSocketId, socketPath, mode string) error {
	md := metadata.Pairs(
		"authorization", c.AccessKey,
		"unixsocket-id", unixSocketId,
	)
	ctx = metadata.NewOutgoingContext(ctx, md)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.unixSocketClient.UnixSocket(ctx)
	if err != nil {
		return fmt.Errorf("failed to create UnixSocket stream: %w", err)
	}

	startReq := &pb.UnixSocketRequest{
		Request: &pb.UnixSocketRequest_StartRequest{
			StartRequest: &pb.UnixSocketStartRequest{
				SocketPath: socketPath,
			},
		},
	}
	if err := stream.Send(startReq); err != nil {
		return fmt.Errorf("failed to send UnixSocket start request: %w", err)
	}

	errCh := make(chan error, 2)

	// writer goroutine (SSH -> gRPC)
	go func() {
		defer func() { _ = stream.CloseSend() }()

		buf := make([]byte, 32*1024)
		for {
			n, rerr := upstream.Read(buf)
			if rerr != nil {
				if rerr == io.EOF {
					errCh <- nil
				} else {
					errCh <- fmt.Errorf("ssh read: %w", rerr)
				}
				return
			}
			if n == 0 {
				continue
			}
			if serr := stream.Send(&pb.UnixSocketRequest{
				Request: &pb.UnixSocketRequest_Data{
					Data: buf[:n],
				},
			}); serr != nil {
				errCh <- fmt.Errorf("grpc send: %w", serr)
				return
			}
			c.counters.AddIn(n)
		}
	}()

	// reader goroutine (gRPC -> SSH)
	go func() {
		for {
			resp, rerr := stream.Recv()
			if rerr != nil {
				if rerr == io.EOF {
					errCh <- nil
				} else {
					errCh <- fmt.Errorf("grpc recv: %w", rerr)
				}
				return
			}
			if _, werr := upstream.Write(resp.Data); werr != nil {
				errCh <- fmt.Errorf("ssh write: %w", werr)
				return
			}
			c.counters.AddOut(len(resp.Data))
		}
	}()

	err = <-errCh

	// drain the second result
	select {
	case <-errCh:
	default:
	}

	return err
}

// RunPortForward sets up a port forward over gRPC and bridges it with the SSH channel.
func (c *K8shelld_v11) RunPortForward(ctx context.Context, upstream api.BufferedReadWriter,
	portForwardID, destinationIP string, destinationPort uint32) error {
	if destinationIP == "" {
		destinationIP = "localhost"
	}

	md := metadata.Pairs(
		"authorization", c.AccessKey,
		"portforward-id", portForwardID,
	)
	ctx = metadata.NewOutgoingContext(ctx, md)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.pfClient.PortForward(ctx)
	if err != nil {
		return fmt.Errorf("failed to create PortForward stream: %w", err)
	}

	startReq := &pb.PortForwardRequest{
		Request: &pb.PortForwardRequest_Destination{
			Destination: &pb.Destination{
				Ip:   destinationIP,
				Port: destinationPort,
			},
		},
	}
	if err := stream.Send(startReq); err != nil {
		return fmt.Errorf("failed to send PortForward destination: %w", err)
	}

	errCh := make(chan error, 2)

	// writer goroutine (SSH -> gRPC)
	go func() {
		defer func() { _ = stream.CloseSend() }()

		buf := make([]byte, 32*1024)
		for {
			n, rerr := upstream.Read(buf)
			if rerr != nil {
				if rerr == io.EOF {
					errCh <- nil
				} else {
					errCh <- fmt.Errorf("ssh read: %w", rerr)
				}
				return
			}
			if n == 0 {
				continue
			}
			if serr := stream.Send(&pb.PortForwardRequest{
				Request: &pb.PortForwardRequest_Data{
					Data: buf[:n],
				},
			}); serr != nil {
				errCh <- fmt.Errorf("grpc send: %w", serr)
				return
			}
			c.counters.AddIn(n)
		}
	}()

	// reader goroutine (gRPC -> SSH)
	go func() {
		for {
			resp, rerr := stream.Recv()
			if rerr != nil {
				if rerr == io.EOF {
					errCh <- nil
				} else {
					errCh <- fmt.Errorf("grpc recv: %w", rerr)
				}
				return
			}
			if _, werr := upstream.Write(resp.Data); werr != nil {
				errCh <- fmt.Errorf("ssh write: %w", werr)
				return
			}
			c.counters.AddOut(len(resp.Data))
		}
	}()

	err = <-errCh

	// drain the second result
	select {
	case <-errCh:
	default:
	}
	return err
}

// RunExec executes a command in a remote shell over gRPC.
func (c *K8shelld_v11) RunExec(ctx context.Context, upstream api.BufferedReadWriter, execID string,
	command string, shellBinary string, envVars []string, signalChan <-chan string) (int32, error) {

	md := metadata.Pairs("authorization", c.AccessKey, "exec-id", execID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.execClient.Exec(ctx)
	if err != nil {
		return 1, fmt.Errorf("failed to create exec stream: %w", err)
	}

	startReq := &pb.ExecRequest{
		Request: &pb.ExecRequest_CommandDetails{
			CommandDetails: &pb.CommandDetails{
				Command:     command,
				ShellBinary: shellBinary,
				EnvVars:     envVars,
			},
		},
	}
	if err := stream.Send(startReq); err != nil {
		return 1, fmt.Errorf("failed to send exec command: %w", err)
	}

	var wg sync.WaitGroup
	var writerErr, readerErr error
	exitCodeCh := make(chan int32, 1)

	// helper to send signals
	sendSignal := func(signalName string) {
		signalReq := &pb.ExecRequest{
			Request: &pb.ExecRequest_Signal{
				Signal: signalName,
			},
		}
		if err := stream.Send(signalReq); err != nil {
			c.log.Error().Err(err).Msgf("Failed to send signal %s to exec process %s", signalName, execID)
		} else {
			c.log.Debug().Msgf("Successfully sent signal %s to exec process %s", signalName, execID)
		}
	}

	// writer goroutine (SSH -> gRPC)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stream.CloseSend()

		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				return
			case signalName := <-signalChan:
				sendSignal(signalName)
			default:
			}

			size, err := upstream.ReadBufferSize()
			if err != nil {
				if err == io.EOF {
					return
				}
				writerErr = fmt.Errorf("ssh buffer check: %w", err)
				return
			}

			if size > 0 {
				n, rerr := upstream.Read(buf)
				if rerr != nil {
					if rerr == io.EOF {
						return
					}
					writerErr = fmt.Errorf("ssh read: %w", rerr)
					return
				}
				if n == 0 {
					continue
				}
				if serr := stream.Send(&pb.ExecRequest{
					Request: &pb.ExecRequest_Input{
						Input: buf[:n],
					},
				}); serr != nil {
					writerErr = fmt.Errorf("grpc send: %w", serr)
					return
				}
				c.counters.AddIn(n)
			} else {
				select {
				case <-ctx.Done():
					return
				case signalName := <-signalChan:
					sendSignal(signalName)
				case <-time.After(10 * time.Millisecond):
					// Continue checking
				}
			}
		}
	}()

	// reader goroutine (gRPC -> SSH)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()

		stderr := upstream.Stderr()

		for {
			resp, rerr := stream.Recv()
			if rerr != nil {
				if rerr == io.EOF {
					return
				}
				readerErr = fmt.Errorf("grpc recv: %w", rerr)
				return
			}

			switch r := resp.Response.(type) {
			case *pb.ExecResponse_Stdout:
				if _, err := upstream.Write(r.Stdout); err != nil {
					readerErr = fmt.Errorf("ssh write: %w", err)
					return
				}
				c.counters.AddOut(len(r.Stdout))
			case *pb.ExecResponse_Stderr:
				if _, err := stderr.Write(r.Stderr); err != nil {
					readerErr = fmt.Errorf("ssh write: %w", err)
					return
				}
				c.counters.AddOut(len(r.Stderr))
			case *pb.ExecResponse_ExitCode:
				exitCodeCh <- r.ExitCode
				return
			default:
				readerErr = fmt.Errorf("unknown exec response type")
				return
			}
		}
	}()

	wg.Wait()

	var exitCode int32 = 0
	select {
	case exitCode = <-exitCodeCh:
	default:
		if writerErr != nil || readerErr != nil {
			exitCode = 1
		}
	}

	if writerErr != nil {
		c.log.Debug().Msgf("Exit code is %d, there is writeErr: %v", exitCode, writerErr)
		return exitCode, writerErr
	}
	if readerErr != nil {
		c.log.Debug().Msgf("Exit code is %d, there is readerErr: %v", exitCode, readerErr)
		return exitCode, readerErr
	}

	c.log.Debug().Msgf("Exit code is %d", exitCode)

	return exitCode, nil
}
