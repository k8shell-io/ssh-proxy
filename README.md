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
4. Each channel action (shell, exec, sftp, agent-forward) is evaluated by the authz service (if configured)
5. Channel requests are proxied through k8shelld; sessions are tracked via the session service

### Authorization

When an `authz` service address is configured, every SSH action is evaluated before the operation begins. The authz service can also return a `RecordObligation` that overrides the static per-channel recording settings for that session. When authz is not configured, the server falls back to the static `recording` config.

### Forking mode

When `server.forking: true`, ssh-proxy spawns a subprocess per connection, passing the socket via fd 3:

```
SSH Client → acceptConnections() → startSubProcess()
  └── spawns: ./ssh-proxy --child --config config.yaml
      └── HandleConnectionChildProcess() → handleConnection()
```

## Getting started

**Prerequisites:** Go 1.24+, access to identity/session/provisioner/k8shelld services.

```bash
# Build
make build

# Run (uses config/config.yaml by default)
./bin/ssh-proxy

# Flags
./bin/ssh-proxy --config config/config.yaml   # config path
./bin/ssh-proxy --logtext                     # human-readable log output
./bin/ssh-proxy -v                            # print version and exit
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
| `internal/server` | SSH server, auth, channel dispatch, session/exec/sftp/agent handling, authz evaluation |
| `internal/workspace` | k8shelld gRPC client, workspace provisioning, client info display |
