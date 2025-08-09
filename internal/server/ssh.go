package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	identity "github.com/k8shell-io/identity/pkg/client"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	"github.com/k8shell-io/ssh-proxy/internal/config"
	"github.com/k8shell-io/ssh-proxy/internal/log"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

var (
	SSHPROXY_VERSION = "0.0.0"
	SSHPROXY_COMMIT  = "0000000"
	SERVER_VERSION   = fmt.Sprintf("SSH-2.0-ssh-proxy_%s/%s k8shell.io", SSHPROXY_VERSION, SSHPROXY_COMMIT)
)

// Server represents the SSH server that handles incoming connections and authentication.
type Server struct {
	Config      *config.Config
	log         *zerolog.Logger
	listener    net.Listener
	sshConfig   *ssh.ServerConfig
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	identity    *identity.Client
	provisioner *provisioner.Client
	useForking  bool
	configPath  string
}

// NewClients creates new instances of the identity and provisioner clients.
func NewClients(config *config.Config) (*identity.Client, *provisioner.Client) {
	identityConfig := identity.Config{
		BaseURL: config.Identity.BaseURL,
		APIKey:  config.Identity.APIKey,
		Timeout: config.Identity.Timeout,
	}
	identityClient := identity.NewClient(identityConfig)

	provisionerConfig := provisioner.Config{
		BaseURL: config.Provisioner.BaseURL,
		APIKey:  config.Provisioner.APIKey,
		Timeout: config.Provisioner.Timeout,
	}
	provisionerClient := provisioner.NewClient(provisionerConfig)

	return identityClient, provisionerClient
}

// NewServer creates a new SSH server instance.
func NewServer(configPath string, useForking bool) (*Server, error) {
	log := log.NewLogger("ssh-server")

	config, err := config.NewConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		Config:     config,
		log:        log,
		ctx:        ctx,
		cancel:     cancel,
		configPath: configPath,
		useForking: useForking,
	}

	if err := server.initSSHConfig(); err != nil {
		return nil, fmt.Errorf("failed to initialize SSH config: %w", err)
	}

	if !useForking {
		identityClient, provisionerClient := NewClients(config)
		server.identity = identityClient
		server.provisioner = provisionerClient
	}

	return server, nil
}

// initSSHConfig initializes the SSH server configuration with callbacks and host key.
func (s *Server) initSSHConfig() error {
	s.sshConfig = &ssh.ServerConfig{
		// SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
		ServerVersion:               SERVER_VERSION,
		KeyboardInteractiveCallback: s.AuthKeyboardInteractive,
		PublicKeyCallback:           s.AuthPublicKey,
		PasswordCallback:            s.AuthPassword,
		MaxAuthTries:                6,
		AllowedAuthsCallback:        s.AllowedAuthsCallback,
	}

	serverKey, err := s.Config.GetServerKey()
	if err != nil {
		return fmt.Errorf("failed to load server key: %w", err)
	}
	s.sshConfig.AddHostKey(serverKey)
	s.log.Info().Msgf("SSH server initialized with server key: %s", serverKey.PublicKey().Type())

	return nil
}

// HandleConnectionFileDescriptor handles a connection from a file descriptor
// It is called when a new connection is accepted and processed in a subprocess when forking is enabled.
func HandleConnectionFileDescriptor(fd int, configPath string) error {
	// get the connection from file descriptor
	file := os.NewFile(uintptr(fd), "connection")
	defer file.Close()

	conn, err := net.FileConn(file)
	if err != nil {
		return fmt.Errorf("failed to create connection from file descriptor: %w", err)
	}
	defer conn.Close()

	config, err := config.NewConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger := log.NewLogger("ssh-server")
	logger.Info().Msgf("Handling connection from file descriptor %d", fd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &Server{
		Config:     config,
		ctx:        ctx,
		cancel:     cancel,
		log:        logger,
		configPath: configPath,
	}

	identityClient, provisionerClient := NewClients(config)
	server.identity = identityClient
	server.provisioner = provisionerClient

	if err := server.initSSHConfig(); err != nil {
		return fmt.Errorf("failed to initialize SSH config: %w", err)
	}

	server.handleConnectionDirect(conn)

	return nil
}

// handleConnectionDirect processes a single SSH connection without wait group management
// This is used when forking is disabled
func (s *Server) handleConnectionDirect(netConn net.Conn) {
	defer netConn.Close()

	s.log.Info().Msgf("New SSH connection from %s", netConn.RemoteAddr().String())
	sshConn, channels, requests, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		s.log.Error().Msgf("Failed to perform SSH handshake: %v", err)
		return
	}
	defer sshConn.Close()

	s.log.Info().Msgf("SSH handshake completed for user %s from %s",
		sshConn.User(),
		sshConn.RemoteAddr().String(),
	)

	go s.handleGlobalRequests(requests)
	s.handleChannels(sshConn, channels)
}

// Start begins listening for SSH connections on the configured port
func (s *Server) Start() error {
	address := fmt.Sprintf(":%d", s.Config.Ssh.Port)

	s.log.Info().
		Int("port", s.Config.Ssh.Port).
		Msg("Starting SSH proxy server")

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}

	s.listener = listener

	s.log.Info().
		Str("address", address).
		Msg("SSH proxy server listening")

	// Start accepting connections in a goroutine
	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// acceptConnections listens for incoming SSH connections and handles them.
// When forking is enabled, it spawns a new process for each connection.
func (s *Server) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			s.log.Info().Msg("Stopping connection acceptance due to context cancellation")
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.log.Error().Err(err).Msg("Failed to accept connection")
				continue
			}
		}

		if s.useForking {
			s.wg.Add(1)
			go s.handleConnectionSubProcess(conn)
		} else {
			s.wg.Add(1)
			go s.handleConnection(conn)
		}
	}
}

// handleConnectionSubProcess spawns a new process to handle the SSH connection in a subprocess
func (s *Server) handleConnectionSubProcess(netConn net.Conn) {
	defer s.wg.Done()
	defer netConn.Close()

	s.log.Info().Msgf("Spawning subprocess for SSH connection from %s", netConn.RemoteAddr().String())

	tcpConn, ok := netConn.(*net.TCPConn)
	if !ok {
		s.log.Error().Msg("Connection is not a TCP connection")
		return
	}

	connFile, err := tcpConn.File()
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to get connection file descriptor")
		return
	}
	defer connFile.Close()

	var optLogtext string = ""
	if !log.JsonLogger {
		optLogtext = "--logtext"
	}
	cmd := exec.Command(os.Args[0], "--fd", "3", "--config", s.configPath, optLogtext)
	cmd.ExtraFiles = []*os.File{connFile}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SSH_PROXY_PORT=%d", s.Config.Ssh.Port),
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	err = cmd.Start()
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to start subprocess for connection")
		return
	}

	s.log.Info().Msgf("Subprocess started for SSH connection, pid: %d", cmd.Process.Pid)
	go func() {
		err := cmd.Wait()
		if err != nil {
			s.log.Error().Msgf("Subprocess exited with error, pid: %d, error: %v", cmd.Process.Pid, err)
		}
	}()
}

// handleConnection processes a single SSH connection
func (s *Server) handleConnection(netConn net.Conn) {
	defer s.wg.Done()
	defer netConn.Close()

	s.log.Info().Msgf("New SSH connection from %s", netConn.RemoteAddr().String())

	sshConn, channels, requests, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		s.log.Error().Msgf("Failed to perform SSH handshake: %v", err)
		return
	}
	defer sshConn.Close()
	s.log.Info().Msgf("SSH handshake completed for user %s", sshConn.User())

	go s.handleGlobalRequests(requests)
	s.handleChannels(sshConn, channels)
}

// handleGlobalRequests processes SSH global requests
func (s *Server) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		s.log.Debug().Msgf("Received global request: type=%s, want_reply=%t", req.Type, req.WantReply)

		// Reject all global requests for now
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// handleChannels handles SSH channel requests.
func (s *Server) handleChannels(sshConn *ssh.ServerConn, channels <-chan ssh.NewChannel) {
	for newChannel := range channels {
		s.log.Debug().Msgf("Received channel request: type=%s", newChannel.ChannelType())

		state := GetState(sshConn)
		if state.User == nil {
			s.log.Error().Msgf("User not found for connection %s, rejecting channel request", sshConn.User())
			newChannel.Reject(ssh.UnknownChannelType, "user not found")
			continue
		}

		switch newChannel.ChannelType() {
		case "session":
			go s.handleSessionChannel(sshConn, state, newChannel)
		case "direct-tcpip":
			// Handle direct TCP/IP channel
		default:
			s.log.Warn().Msgf("Unsupported channel type: %s", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "channel type not supported")
		}
	}
}

// Stop gracefully shuts down the SSH server
func (s *Server) Stop() {
	s.log.Info().Msg("Stopping SSH server...")
	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	s.wg.Wait()
	s.log.Info().Msg("SSH server stopped")
}
