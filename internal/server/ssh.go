package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/k8shell-io/ssh-proxy/internal/config"
	"github.com/k8shell-io/ssh-proxy/internal/log"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Config     *config.Config
	Logger     *zerolog.Logger
	listener   net.Listener
	sshConfig  *ssh.ServerConfig
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	useForking bool
	configPath string
	hostKey    ssh.Signer // Host key loaded from file
}

func NewServer(configPath string) (*Server, error) {
	config, err := config.NewConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	server := &Server{
		Config:     config,
		Logger:     log.NewLogger("ssh-server"),
		ctx:        ctx,
		cancel:     cancel,
		configPath: configPath,
	}

	if err := server.initSSHConfig(); err != nil {
		return nil, fmt.Errorf("failed to initialize SSH config: %w", err)
	}

	if err := server.Start(); err != nil {
		return nil, fmt.Errorf("failed to start SSH server: %w", err)
	}

	return server, nil
}

// EnableForking enables subprocess-based connection handling
func (s *Server) EnableForking() {
	s.useForking = true
	s.Logger.Info().Msg("Enabled subprocess-based connection handling")
}

// HandleConnectionFromFD handles a connection from a file descriptor (subprocess mode)
func HandleConnectionFromFD(fd int, configPath string) error {
	// Recreate the connection from file descriptor
	file := os.NewFile(uintptr(fd), "connection")
	defer file.Close()

	conn, err := net.FileConn(file)
	if err != nil {
		return fmt.Errorf("failed to create connection from file descriptor: %w", err)
	}
	defer conn.Close()

	// Load configuration
	config, err := config.NewConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger := log.NewLogger("ssh-subprocess")
	logger.Info().
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("Subprocess handling SSH connection")

	// Initialize SSH config for this subprocess (will load the same host key from file)
	server := &Server{
		Config:     config,
		Logger:     logger,
		configPath: configPath,
	}

	if err := server.initSSHConfig(); err != nil {
		return fmt.Errorf("failed to initialize SSH config: %w", err)
	}

	// Handle the connection directly (without wait group since this is subprocess)
	server.handleConnectionDirect(conn)

	return nil
}

// handleConnectionDirect processes a single SSH connection without wait group management
func (s *Server) handleConnectionDirect(netConn net.Conn) {
	defer netConn.Close()

	s.Logger.Info().
		Str("remote_addr", netConn.RemoteAddr().String()).
		Msg("New SSH connection")

	// Perform SSH handshake
	sshConn, channels, requests, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		s.Logger.Error().
			Err(err).
			Str("remote_addr", netConn.RemoteAddr().String()).
			Msg("Failed to perform SSH handshake")
		return
	}
	defer sshConn.Close()

	s.Logger.Info().
		Str("user", sshConn.User()).
		Str("remote_addr", sshConn.RemoteAddr().String()).
		Msg("SSH handshake completed")

	// Handle global requests in a goroutine
	go s.handleGlobalRequests(requests)

	// Handle channels
	s.handleChannels(channels)
}

// initSSHConfig initializes the SSH server configuration by loading the host key from file
func (s *Server) initSSHConfig() error {
	// Load host key from file
	hostKey, err := s.loadHostKey()
	if err != nil {
		return fmt.Errorf("failed to load host key: %w", err)
	}

	s.hostKey = hostKey

	// Configure SSH server
	s.sshConfig = &ssh.ServerConfig{
		// PublicKeyCallback is called when a client offers a public key for authentication
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			// For now, accept all public keys - you can implement proper authentication here
			s.Logger.Info().
				Str("user", conn.User()).
				Str("remote_addr", conn.RemoteAddr().String()).
				Msg("SSH public key authentication attempt")
			return &ssh.Permissions{}, nil
		},
		// PasswordCallback is called when a client offers a password for authentication
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// For now, accept all passwords - you can implement proper authentication here
			s.Logger.Info().
				Str("user", conn.User()).
				Str("remote_addr", conn.RemoteAddr().String()).
				Msg("SSH password authentication attempt")
			return &ssh.Permissions{}, nil
		},
	}

	// Add the host key to the server configuration
	s.sshConfig.AddHostKey(hostKey)

	s.Logger.Info().
		Str("server_key_path", s.Config.Ssh.ServerKey).
		Msg("SSH server initialized with server key")

	return nil
}

// loadServerKey loads the SSH server key from the configured file path
func (s *Server) loadHostKey() (ssh.Signer, error) {
	hostKeyPath := s.Config.Ssh.ServerKey
	if hostKeyPath == "" {
		return nil, fmt.Errorf("server key path not configured")
	}

	// Read the private key file
	privateKeyBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key file '%s': %w", hostKeyPath, err)
	}

	// Parse the private key (supports PEM format)
	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key from '%s': %w", hostKeyPath, err)
	}

	s.Logger.Info().
		Str("host_key_path", hostKeyPath).
		Str("key_type", signer.PublicKey().Type()).
		Msg("Successfully loaded SSH host key")

	return signer, nil
}

// Start begins listening for SSH connections on the configured port
func (s *Server) Start() error {
	address := fmt.Sprintf(":%d", s.Config.Ssh.Port)

	s.Logger.Info().
		Int("port", s.Config.Ssh.Port).
		Msg("Starting SSH proxy server")

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}

	s.listener = listener

	s.Logger.Info().
		Str("address", address).
		Msg("SSH proxy server listening")

	// Start accepting connections in a goroutine
	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// acceptConnections handles incoming SSH connections
func (s *Server) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.ctx.Done():
					return
				default:
					s.Logger.Error().Err(err).Msg("Failed to accept connection")
					continue
				}
			}

			// Handle each connection - either in subprocess or goroutine
			if s.useForking {
				s.wg.Add(1)
				go s.handleConnectionWithProcess(conn)
			} else {
				s.wg.Add(1)
				go s.handleConnection(conn)
			}
		}
	}
}

// handleConnectionWithProcess spawns a new process to handle the SSH connection
func (s *Server) handleConnectionWithProcess(netConn net.Conn) {
	defer s.wg.Done()
	defer netConn.Close()

	s.Logger.Info().
		Str("remote_addr", netConn.RemoteAddr().String()).
		Msg("Spawning subprocess for SSH connection")

	// Get the file descriptor for the connection
	tcpConn, ok := netConn.(*net.TCPConn)
	if !ok {
		s.Logger.Error().Msg("Connection is not a TCP connection")
		return
	}

	connFile, err := tcpConn.File()
	if err != nil {
		s.Logger.Error().Err(err).Msg("Failed to get connection file descriptor")
		return
	}
	defer connFile.Close()

	// Spawn a subprocess to handle this connection
	cmd := exec.Command(os.Args[0], "--fd", "3", "--config", s.configPath)
	cmd.ExtraFiles = []*os.File{connFile}
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SSH_PROXY_PORT=%d", s.Config.Ssh.Port),
	)

	// Set process group to allow proper cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	err = cmd.Start()
	if err != nil {
		s.Logger.Error().Err(err).Msg("Failed to start subprocess for connection")
		return
	}

	s.Logger.Info().
		Int("pid", cmd.Process.Pid).
		Str("remote_addr", netConn.RemoteAddr().String()).
		Msg("Subprocess started for SSH connection")

	// Wait for the subprocess to complete
	go func() {
		err := cmd.Wait()
		if err != nil {
			s.Logger.Error().
				Err(err).
				Int("pid", cmd.Process.Pid).
				Msg("Subprocess exited with error")
		} else {
			s.Logger.Info().
				Int("pid", cmd.Process.Pid).
				Msg("Subprocess completed successfully")
		}
	}()
}

// handleConnection processes a single SSH connection
func (s *Server) handleConnection(netConn net.Conn) {
	defer s.wg.Done()
	defer netConn.Close()

	s.Logger.Info().
		Str("remote_addr", netConn.RemoteAddr().String()).
		Msg("New SSH connection")

	// Perform SSH handshake
	sshConn, channels, requests, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		s.Logger.Error().
			Err(err).
			Str("remote_addr", netConn.RemoteAddr().String()).
			Msg("Failed to perform SSH handshake")
		return
	}
	defer sshConn.Close()

	s.Logger.Info().
		Str("user", sshConn.User()).
		Str("remote_addr", sshConn.RemoteAddr().String()).
		Msg("SSH handshake completed")

	// Handle global requests in a goroutine
	go s.handleGlobalRequests(requests)

	// Handle channels
	s.handleChannels(channels)
}

// handleGlobalRequests processes SSH global requests
func (s *Server) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		s.Logger.Debug().
			Str("type", req.Type).
			Bool("want_reply", req.WantReply).
			Msg("Received global request")

		// Reject all global requests for now
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// handleChannels processes SSH channel requests
func (s *Server) handleChannels(channels <-chan ssh.NewChannel) {
	for newChannel := range channels {
		s.Logger.Debug().
			Str("channel_type", newChannel.ChannelType()).
			Msg("Received channel request")

		// For now, reject all channel requests
		// In a full SSH proxy implementation, you would forward these to the target server
		newChannel.Reject(ssh.UnknownChannelType, "channel type not supported")
	}
}

// Stop gracefully shuts down the SSH server
func (s *Server) Stop() {
	s.Logger.Info().Msg("Stopping SSH proxy server")

	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	s.wg.Wait()
	s.Logger.Info().Msg("SSH proxy server stopped")
}
