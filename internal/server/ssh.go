package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	log "github.com/k8shell-io/common/logger"
	identity "github.com/k8shell-io/identity/pkg/client"
	provisioner "github.com/k8shell-io/provisioner/pkg/client"
	"github.com/k8shell-io/ssh-proxy/internal/config"
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
func NewServer(configPath string) (*Server, error) {
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
	}

	if err := server.initSSHConfig(); err != nil {
		return nil, fmt.Errorf("failed to initialize SSH config: %w", err)
	}

	if !server.Config.Server.Forking {
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

// HandleConnectionChildProcess handles a connection from a file descriptor
// It is called when a new connection is accepted and processed in a subprocess when forking is enabled.
func HandleConnectionChildProcess(configPath string, ip string, port int) error {
	// get the connection from file descriptor, fd 3 should be the connection
	file := os.NewFile(uintptr(3), "connection")
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
	logger.Info().Msg("Handling connection in the child process")

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

	server.handleConnection(conn, true, ip, port)

	return nil
}

// handleConnection processes a single SSH connection
func (s *Server) handleConnection(netConn net.Conn, isDirect bool, ip string, port int) {
	if !isDirect {
		defer s.wg.Done()
	}
	defer netConn.Close()

	s.log.Info().Msgf("New SSH connection from %s", netConn.RemoteAddr().String())

	sshConn, channels, requests, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		s.log.Error().Msgf("Failed to perform SSH handshake: %v", err)
		return
	}
	defer sshConn.Close()
	s.log.Info().Msgf("SSH handshake completed for user %s", sshConn.User())

	connInfo, err := s.GetConnInfo(sshConn)
	if err != nil {
		s.log.Error().Msgf("Failed to get connection info: %v", err)
		return
	}
	if connInfo.User == nil {
		s.log.Error().Msgf("There is no user identity associated with username %s. Cannot handle connection.",
			sshConn.User())
		return
	}
	connInfo.clientIP = ip
	connInfo.clientPort = port
	defer connInfo.Close()

	go s.handleGlobalRequests(requests)
	s.handleChannels(sshConn, connInfo, channels)

	s.log.Info().Msgf("Connection closed for user %s from %s", sshConn.User(), sshConn.RemoteAddr())
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

		if s.Config.Server.Forking {
			s.wg.Add(1)
			go s.startSubProcess(conn)
		} else {
			s.wg.Add(1)
			go s.handleConnectionWithProxyProtocol(conn, false)
		}
	}
}

// startSubProcess spawns a new process to handle the SSH connection in a subprocess
func (s *Server) startSubProcess(netConn net.Conn) {
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
	cmd := exec.Command(os.Args[0], "--config", s.configPath, "--child", optLogtext)
	cmd.ExtraFiles = []*os.File{connFile}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

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

// GetProxyID generates a unique proxy identifier based on hostname
// If hostname matches Kubernetes deployment pod pattern, it uses the pod hash as proxy-id.
// Otherwise uses "local" as proxy-id
func GetProxyID() string {
	var proxyID string

	hostname, err := os.Hostname()
	if err != nil {
		proxyID = "local"
	} else {
		if podHash := extractPodHash(hostname); podHash != "" {
			proxyID = podHash
		} else {
			proxyID = "local"
		}
	}
	return proxyID
}

// extractPodHash extracts the pod hash from a Kubernetes deployment pod hostname
// Returns empty string if the hostname doesn't match the expected pattern
func extractPodHash(hostname string) string {
	parts := strings.Split(hostname, "-")

	if len(parts) < 3 {
		return ""
	}

	podHash := parts[len(parts)-1]
	if len(podHash) == 5 && isValidPodHash(podHash) {
		return podHash
	}

	return ""
}

func isValidPodHash(hash string) bool {
	for _, char := range hash {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')) {
			return false
		}
	}
	return true
}

// ParseProxyProtocolV1 parses and CONSUMES the proxy protocol header
func ParseProxyProtocolV1(conn net.Conn) (net.Conn, string, int, error) {
	reader := bufio.NewReader(conn)

	// Peek to check if PROXY protocol is present
	peek, err := reader.Peek(6)
	if err != nil {
		if err == io.EOF && len(peek) == 0 {
			return conn, "", 0, nil // No data available
		}
		return conn, "", 0, fmt.Errorf("failed to peek at connection: %w", err)
	}

	// No proxy protocol - return connection that handles peeked data
	if !bytes.HasPrefix(peek, []byte("PROXY ")) {
		return &BufferedConn{Conn: conn, reader: reader}, "", 0, nil
	}

	// CONSUME the proxy protocol line
	lineBytes, err := reader.ReadBytes('\n')
	if err != nil {
		return conn, "", 0, fmt.Errorf("failed to read proxy protocol line: %w", err)
	}

	line := strings.TrimSpace(string(lineBytes))
	parts := strings.Split(line, " ")
	if len(parts) < 6 {
		return conn, "", 0, errors.New("malformed PROXY protocol header: missing required fields")
	}

	realClientIP := parts[2]
	realClientPort, err := strconv.Atoi(parts[4])
	if err != nil {
		return conn, "", 0, fmt.Errorf("invalid client port: %w", err)
	}

	// Return connection that uses the buffered reader (proxy protocol already consumed)
	return &BufferedConn{Conn: conn, reader: reader}, realClientIP, realClientPort, nil
}

// Simple buffered connection wrapper
type BufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (bc *BufferedConn) Read(b []byte) (int, error) {
	return bc.reader.Read(b)
}

// Update handleConnectionWithProxyProtocol
func (s *Server) handleConnectionWithProxyProtocol(netConn net.Conn, isDirect bool) {
	if !isDirect {
		defer s.wg.Done()
	}
	defer netConn.Close()

	var ip string
	var port int
	remoteAddr := netConn.RemoteAddr()
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		ip = tcpAddr.IP.String()
		port = tcpAddr.Port
	} else {
		s.log.Error().Msgf("Unexpected addr type: %T\n", remoteAddr)
		netConn.Close()
		return
	}

	var cleanConn net.Conn = netConn

	if s.Config.Server.ProxyProtocol {
		var err error
		cleanConn, ip, port, err = ParseProxyProtocolV1(netConn)
		if err != nil {
			s.log.Error().Err(err).Msg("Failed to parse PROXY protocol")
			return
		}
		if ip != "" {
			s.log.Debug().Msgf("Parsed PROXY protocol header: client IP %s, port %d", ip, port)
		}
	}

	s.handleConnection(cleanConn, isDirect, ip, port)
}
