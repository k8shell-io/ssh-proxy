package k8shelld

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

type Client struct {
	conn         *grpc.ClientConn
	infoClient   pb.InfoServiceClient
	remoteClient pb.RemoteOSServiceClient
	AccessKey    string
}

func NewClient(address string, port int, accessKey string, tlsCert string) (*Client, error) {
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

	return &Client{
		conn:         conn,
		infoClient:   pb.NewInfoServiceClient(conn),
		remoteClient: pb.NewRemoteOSServiceClient(conn),
		AccessKey:    accessKey,
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) GetVersion(ctx context.Context) (*pb.VersionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	md := metadata.Pairs("authorization", c.AccessKey)
	ctx = metadata.NewOutgoingContext(ctx, md)

	req := &pb.VersionRequest{}
	return c.infoClient.Version(ctx, req)
}

// StartShell creates a shell session and bridges it with the SSH channel
func (c *Client) StartShell(ctx context.Context, channel ssh.Channel, sessionId string, envVars []string,
	width, height uint32) error {
	md := metadata.Pairs("authorization", c.AccessKey, "session-id", sessionId)
	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := c.remoteClient.Shell(ctx)
	if err != nil {
		return fmt.Errorf("failed to create shell stream: %w", err)
	}

	startReq := &pb.ShellRequest{
		Request: &pb.ShellRequest_StartRequest{
			StartRequest: &pb.ShellStartRequest{
				CmdShell:   "/bin/sh",
				SetEnvVars: envVars,
				UsePty:     true,
				Width:      width,
				Height:     height,
			},
		},
	}

	if err := stream.Send(startReq); err != nil {
		return fmt.Errorf("failed to send start request: %w", err)
	}

	// Start goroutines to handle bidirectional communication
	errChan := make(chan error, 2)

	// Goroutine to read from SSH channel and send to gRPC stream
	go func() {
		defer stream.CloseSend()

		buffer := make([]byte, 1024)
		for {
			n, err := channel.Read(buffer)
			if err != nil {
				if err == io.EOF {
					errChan <- nil
					return
				}
				errChan <- fmt.Errorf("failed to read from SSH channel: %w", err)
				return
			}

			req := &pb.ShellRequest{
				Request: &pb.ShellRequest_Data{
					Data: buffer[:n],
				},
			}

			if err := stream.Send(req); err != nil {
				errChan <- fmt.Errorf("failed to send data to stream: %w", err)
				return
			}
		}
	}()

	// Goroutine to read from gRPC stream and send to SSH channel
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					errChan <- nil
					return
				}
				errChan <- fmt.Errorf("failed to receive from stream: %w", err)
				return
			}

			switch r := resp.Response.(type) {
			case *pb.ShellResponse_Data:
				if _, err := channel.Write(r.Data); err != nil {
					errChan <- fmt.Errorf("failed to write to SSH channel: %w", err)
					return
				}
			case *pb.ShellResponse_Terminate:
				if r.Terminate {
					errChan <- nil
					return
				}
			}
		}
	}()

	// Wait for either goroutine to finish or error
	return <-errChan
}

// ResizeTerminal resizes the terminal
func (c *Client) ResizeTerminal(ctx context.Context, sessionId string, width, height uint32) error {
	md := metadata.Pairs("authorization", c.AccessKey, "session-id", sessionId)
	ctx = metadata.NewOutgoingContext(ctx, md)

	req := &pb.ResizeTerminalRequest{
		Width:  width,
		Height: height,
	}

	_, err := c.remoteClient.ResizeTerminal(ctx, req)
	return err
}

// StartUnixSocket creates a Unix socket session and bridges it with the SSH channel
func (c *Client) StartUnixSocket(ctx context.Context, channel ssh.Channel, sessionID string, socketPath string) error {
	md := metadata.Pairs(
		"authorization", c.AccessKey,
		"session-id", sessionID,
	)
	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := c.remoteClient.UnixSocket(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket stream: %w", err)
	}

	startReq := &pb.UnixSocketRequest{
		Request: &pb.UnixSocketRequest_StartRequest{
			StartRequest: &pb.UnixSocketStartRequest{
				SocketPath: socketPath,
			},
		},
	}

	if err := stream.Send(startReq); err != nil {
		return fmt.Errorf("failed to send Unix socket start request: %w", err)
	}

	errChan := make(chan error, 2)

	// Read from SSH channel and send to gRPC stream
	go func() {
		defer stream.CloseSend()

		buffer := make([]byte, 1024)
		for {
			n, err := channel.Read(buffer)
			if err != nil {
				if err == io.EOF {
					errChan <- nil
					return
				}
				errChan <- fmt.Errorf("failed to read from SSH channel: %w", err)
				return
			}

			req := &pb.UnixSocketRequest{
				Request: &pb.UnixSocketRequest_Data{
					Data: buffer[:n],
				},
			}

			if err := stream.Send(req); err != nil {
				errChan <- fmt.Errorf("failed to send data to Unix socket stream: %w", err)
				return
			}
		}
	}()

	// Read from gRPC stream and send to SSH channel
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					errChan <- nil
					return
				}
				errChan <- fmt.Errorf("failed to receive from Unix socket stream: %w", err)
				return
			}

			switch r := resp.Response.(type) {
			case *pb.UnixSocketResponse_Data:
				if _, err := channel.Write(r.Data); err != nil {
					errChan <- fmt.Errorf("failed to write to SSH channel: %w", err)
					return
				}
			case *pb.UnixSocketResponse_Terminate:
				if r.Terminate {
					errChan <- nil
					return
				}
			}
		}
	}()

	return <-errChan
}

// StartUnixSocketWithConnection uses an existing SSH channel for Unix socket forwarding
func (c *Client) StartUnixSocketWithConnection(ctx context.Context, sshChannel ssh.Channel, sessionID string, socketPath string) error {
	// Add authorization and session-id metadata
	md := metadata.Pairs(
		"authorization", c.AccessKey,
		"unixsocket-id", "ux-12345",
	)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Create the Unix socket stream
	stream, err := c.remoteClient.UnixSocket(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket stream: %w", err)
	}

	// Send initial Unix socket start request
	startReq := &pb.UnixSocketRequest{
		Request: &pb.UnixSocketRequest_StartRequest{
			StartRequest: &pb.UnixSocketStartRequest{
				SocketPath: socketPath,
			},
		},
	}

	if err := stream.Send(startReq); err != nil {
		return fmt.Errorf("failed to send Unix socket start request: %w", err)
	}

	// Start goroutines to handle bidirectional communication
	errChan := make(chan error, 2)

	// Goroutine to read from SSH channel and send to gRPC stream
	go func() {
		defer stream.CloseSend()

		buffer := make([]byte, 1024)
		for {
			n, err := sshChannel.Read(buffer)
			if err != nil {
				if err == io.EOF {
					errChan <- nil
					return
				}
				errChan <- fmt.Errorf("failed to read from SSH channel: %w", err)
				return
			}

			req := &pb.UnixSocketRequest{
				Request: &pb.UnixSocketRequest_Data{
					Data: buffer[:n],
				},
			}

			if err := stream.Send(req); err != nil {
				errChan <- fmt.Errorf("failed to send data to Unix socket stream: %w", err)
				return
			}
		}
	}()

	// Goroutine to read from gRPC stream and send to SSH channel
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					errChan <- nil
					return
				}
				errChan <- fmt.Errorf("failed to receive from Unix socket stream: %w", err)
				return
			}

			switch r := resp.Response.(type) {
			case *pb.UnixSocketResponse_Data:
				if _, err := sshChannel.Write(r.Data); err != nil {
					errChan <- fmt.Errorf("failed to write to SSH channel: %w", err)
					return
				}
			case *pb.UnixSocketResponse_Terminate:
				if r.Terminate {
					errChan <- nil
					return
				}
			}
		}
	}()

	// Wait for either goroutine to finish or error
	return <-errChan
}
