# ssh-proxy

[![Build](https://github.com/k8shell-io/ssh-proxy/actions/workflows/build.yaml/badge.svg)](https://github.com/k8shell-io/ssh-proxy/actions/workflows/build.yaml)

An SSH proxy that acts as a secure gateway into k8shell workspaces. Clients authenticate against ssh-proxy, which then routes traffic to the target workspace through the in-workspace `k8shelld` daemon.

For full documentation see [docs.k8shell.io/concepts/ssh-proxy](https://docs.k8shell.io/concepts/ssh-proxy).

## Architecture

```
SSH Client ──(auth)──► ssh-proxy ──(gRPC)──► k8shelld (workspace) ──► target
```

**Supported channel types:**

| Channel | SSH client usage |
|---|---|
| `session` | Interactive shell, `exec`, `sftp` subsystem |
| `direct-tcpip` | Port forwarding (`-L`), `ProxyCommand -W` |
| `direct-streamlocal` | Unix socket forwarding |

**Authentication:** public key (via identity service), keyboard-interactive (onboarding flow).

**Not supported:** `RemoteForward` (`-R`), `DynamicForward` (`-D`), X11 forwarding — all global requests are rejected.

## Connection flow

1. Client connects and authenticates (public key or keyboard-interactive)
2. ssh-proxy resolves the user's workspace via the identity + provisioner services
3. A gRPC connection is established to `k8shelld` inside the workspace
4. Channel requests (`shell`, `exec`, `sftp`, port-forward) are proxied through k8shelld

### Forking mode

When `server.forking: true`, ssh-proxy spawns a subprocess per connection, passing the socket via fd 3:

```
SSH Client → acceptConnections() → handleConnectionWithProcess()
  └── spawns: ./ssh-proxy --handle-connection-fd 3 --config config.yaml
      └── HandleConnectionFromFD(3) → handleConnection()
```

## Getting started

**Prerequisites:** Go 1.24+, access to identity/session/provisioner/k8shelld services.

```bash
# Build
make build

# Run (uses config/config.yaml by default)
./bin/ssh-proxy

# Flags
./bin/ssh-proxy -c config/config.yaml   # config path
./bin/ssh-proxy -text                   # human-readable log output
./bin/ssh-proxy -v                      # print version and exit
```

## Configuration

Key settings in `config/config.yaml`:

```yaml
server:
  port: 2022
  serverKey: /path/to/server_key        # SSH host key
  forking: false                         # subprocess-per-connection mode
  proxyProtocol: true                    # parse PROXY protocol for real client IP
  maxDirectTCPIPConnections: 15          # per-connection port-forward limit
  recording:
    recordShell: true
    recordDirectTCPIP: true

identity:
  address: identity.k8shell-test:9020

session:
  address: session.k8shell-test:9010
```

## Client SSH config

```ssh-config
Host my-workspace
  Hostname ssh-internal.k8shell-test     # workspace-internal hostname
  User alice
  IdentityFile ~/.ssh/id_rsa
  ProxyCommand ssh -i ~/.ssh/id_rsa -W %h:%p -p 22 alice@app.k8shell.dev
  ForwardAgent yes
  ServerAliveInterval 30
  StrictHostKeyChecking accept-new
```

## Key packages

| Path | Responsibility |
|---|---|
| `internal/server` | SSH server, auth, channel dispatch, session/exec/sftp handling |
| `internal/workspace` | k8shelld gRPC client interface |
