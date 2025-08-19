package workspace

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	pb "github.com/k8shell-io/ssh-proxy/grpc/generated-go/k8shelldpb"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

type K8shelld struct {
	conn         *grpc.ClientConn
	infoClient   pb.InfoServiceClient
	remoteClient pb.RemoteOSServiceClient
	AccessKey    string
}

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
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", address, port), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	return &K8shelld{
		conn:         conn,
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
	cancel()
	_ = channel.Close()

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
	cancel()
	_ = channel.Close()

	// drain possible second result
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
	cancel()
	_ = channel.Close()

	// drain possible second result
	select {
	case <-errCh:
	default:
	}
	return err
}
