package workspace

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"time"

	pb "github.com/k8shell-io/ssh-proxy/grpc/generated-go/k8shelldpb"
	"github.com/k8shell-io/ssh-proxy/internal/log"
	"github.com/rs/zerolog"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

type K8shelld struct {
	conn         *grpc.ClientConn
	log          *zerolog.Logger
	infoClient   pb.InfoServiceClient
	remoteClient pb.RemoteOSServiceClient
	AccessKey    string
}

// KEEPALIVE_TIME defines the time for keepalive pings.
var KEEPALIVE_TIME = 5 * time.Minute

// KEEPALIVE_TIMEOUT defines the timeout for keepalive pings.
var KEEPALIVE_TIMEOUT = 20 * time.Second

func NewK8shelld(address string, port int, accessKey string, tlsCert string) (*K8shelld, error) {
	var creds credentials.TransportCredentials

	if tlsCert != "" {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM([]byte(tlsCert)) {
			return nil, fmt.Errorf("failed to append TLS certificate to pool")
		}

		config := &tls.Config{
			ServerName: address,
			RootCAs:    certPool,
		}
		creds = credentials.NewTLS(config)
	} else {
		// fallback
		config := &tls.Config{
			ServerName:         address,
			InsecureSkipVerify: true,
		}
		creds = credentials.NewTLS(config)
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                KEEPALIVE_TIME,
			Timeout:             KEEPALIVE_TIMEOUT,
			PermitWithoutStream: false,
		}),
	}

	conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", address, port), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	return &K8shelld{
		conn:         conn,
		log:          log.NewLogger("k8shelld"),
		infoClient:   pb.NewInfoServiceClient(conn),
		remoteClient: pb.NewRemoteOSServiceClient(conn),
		AccessKey:    accessKey,
	}, nil
}

func (c *K8shelld) Close() error {
	return c.conn.Close()
}

func (c *K8shelld) GetVersion(ctx context.Context) (*pb.VersionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	md := metadata.Pairs("authorization", c.AccessKey)
	ctx = metadata.NewOutgoingContext(ctx, md)

	req := &pb.VersionRequest{}
	return c.infoClient.Version(ctx, req)
}

// StartShell creates a PTY shell session over gRPC and bridges it with the SSH channel.
func (c *K8shelld) StartShell(ctx context.Context, channel ssh.Channel, sessionId string, envVars []string,
	width, height uint32, usePty bool) error {
	md := metadata.Pairs(
		"authorization", c.AccessKey,
		"session-id", sessionId,
	)
	ctx = metadata.NewOutgoingContext(ctx, md)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.remoteClient.Shell(ctx)
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
			n, rerr := channel.Read(buf)
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
				if _, werr := channel.Write(r.Data); werr != nil {
					errCh <- fmt.Errorf("ssh write: %w", werr)
					return
				}
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
func (c *K8shelld) ResizeTerminal(ctx context.Context, sessionId string, width, height uint32) error {
	md := metadata.Pairs("authorization", c.AccessKey, "session-id", sessionId)
	ctx = metadata.NewOutgoingContext(ctx, md)

	req := &pb.ResizeTerminalRequest{
		Width:  width,
		Height: height,
	}

	_, err := c.remoteClient.ResizeTerminal(ctx, req)
	return err
}

func (c *K8shelld) StartUnixSocket(ctx context.Context, channel ssh.Channel, agentUnixID, socketPath string) error {
	md := metadata.Pairs(
		"authorization", c.AccessKey,
		"unixsocket-id", agentUnixID,
	)
	ctx = metadata.NewOutgoingContext(ctx, md)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.remoteClient.UnixSocket(ctx)
	if err != nil {
		return fmt.Errorf("failed to create UnixSocket stream: %w", err)
	}

	// send initial start request
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
			n, rerr := channel.Read(buf)
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
			case *pb.UnixSocketResponse_Data:
				if _, werr := channel.Write(r.Data); werr != nil {
					errCh <- fmt.Errorf("ssh write: %w", werr)
					return
				}
			case *pb.UnixSocketResponse_Terminate:
				if r.Terminate {
					errCh <- nil
					return
				}
			}
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

func (c *K8shelld) StartPortForward(ctx context.Context, channel ssh.Channel, portForwardID, destinationIP string, destinationPort uint32) error {
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

	stream, err := c.remoteClient.PortForward(ctx)
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
			n, rerr := channel.Read(buf)
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
			case *pb.PortForwardResponse_Data:
				if _, werr := channel.Write(r.Data); werr != nil {
					errCh <- fmt.Errorf("ssh write: %w", werr)
					return
				}
			case *pb.PortForwardResponse_Terminate:
				if r.Terminate {
					errCh <- nil
					return
				}
			default:
				// unknown response type — treat as error to avoid hanging
				errCh <- fmt.Errorf("unknown PortForward response type")
				return
			}
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

// StartExec executes a command in a remote shell over gRPC.
func (c *K8shelld) StartExec(ctx context.Context, channel ssh.Channel, execID string,
	command string, shellBinary string, envVars []string, signalChan <-chan string) (int32, error) {

	md := metadata.Pairs("authorization", c.AccessKey, "exec-id", execID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.remoteClient.Exec(ctx)
	if err != nil {
		return 1, fmt.Errorf("failed to create exec stream: %w", err)
	}

	startReq := &pb.ExecRequest{
		Request: &pb.ExecRequest_CommandDetails{
			CommandDetails: &pb.CommandDetails{
				Command:     command,
				ShellBinary: shellBinary,
				SetEnvVars:  envVars,
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

			size, err := channel.ReadBufferSize()
			if err != nil {
				if err == io.EOF {
					return
				}
				writerErr = fmt.Errorf("ssh buffer check: %w", err)
				return
			}

			if size > 0 {
				n, rerr := channel.Read(buf)
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

		stderr := channel.Stderr()

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
				if _, err := channel.Write(r.Stdout); err != nil {
					readerErr = fmt.Errorf("ssh write: %w", err)
					return
				}
			case *pb.ExecResponse_Stderr:
				if _, err := stderr.Write(r.Stderr); err != nil {
					readerErr = fmt.Errorf("ssh write: %w", err)
					return
				}
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
		return exitCode, writerErr
	}
	if readerErr != nil {
		return exitCode, readerErr
	}

	return exitCode, nil
}
