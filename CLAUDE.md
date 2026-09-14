# ssh-proxy — agent context

## What this repo is

An SSH proxy gateway for k8shell workspaces. It terminates SSH connections, authenticates users via the identity service, provisions workspaces via the provisioner service, and proxies all channel traffic to the in-workspace `k8shelld` gRPC daemon.

## Build and test

```bash
make build          # → bin/ssh-proxy
make test           # unit tests with coverage (installs golangci-lint + gosec first)
make test-static    # golangci-lint + gosec HIGH-severity scan
make test-self      # test-static + build + binary smoke test (what CI runs)
make vendor         # vendor dependencies (required before docker image build)
make image          # alpine image (debug build, while-loop entrypoint)
make image-release  # distroless image (stripped binary)
```

Quick iteration without installing test deps:

```bash
go build ./...
go test ./...
```

Version info is embedded at link time:

```bash
go build -ldflags="-X github.com/k8shell-io/ssh-proxy/internal/server.SSHPROXY_VERSION=v1.2.3 \
  -X github.com/k8shell-io/ssh-proxy/internal/server.SSHPROXY_COMMIT=abc1234" -o bin/ssh-proxy main.go
```

## Key dependency note

`golang.org/x/crypto` is **replaced** in `go.mod` with a fork:

```
replace golang.org/x/crypto v0.43.0 => github.com/k8shell-io/crypto v0.41.1-ssh-proxy
```

This fork adds the `AllowedAuthsCallback` field to `ssh.ServerConfig`, which ssh-proxy uses to advertise available auth methods per-user. Do not remove this replace directive or switch to the upstream package — the feature does not exist upstream.

## Package layout

```
main.go                         — flag parsing, signal handling, server lifecycle
internal/server/
  ssh.go                        — Server struct, listener, connection dispatch, forking, gRPC server lifecycle
  grpc.go                       — sshproxy.v1.SSHProxyService implementation (GetVersionInfo)
  auth.go                       — Public key, password, keyboard-interactive callbacks
  authzcheck.go                 — Authz service evaluation (SSH actions + RecordObligation)
  connection.go                 — Connection/Session state, workspace handshake, session reporting
  session.go                    — shell, exec, sftp, agent-forward channel handling
  directcpip.go                 — direct-tcpip port-forward channel handling
  directstream.go               — direct-streamlocal unix socket channel handling
  nats.go                       — SSH failure event publishing to NATS
  config.go                     — Config structs + defaults (port required; others have defaults)
internal/workspace/
  client.go                     — K8shelldClient interface + ChannelAdapter
  client_v12.go                 — k8shelld gRPC client implementation
  provision.go                  — EnsureWorkspace, workspace provisioning, InfoWriter
```

## Service dependencies

All clients use `gapi.ClientConfig` (address + optional TLS + token file). A service is disabled when its address is empty.

| Config key | Required | Purpose |
|---|---|---|
| `identity` | yes | auth, user lookup, token issuance, device-flow onboarding |
| `provisioner` | yes | workspace lookup and provisioning |
| `k8shelld` | yes | per-workspace gRPC daemon (address resolved at runtime from provisioner) |
| `session` | no | session tracking + per-session recording |
| `authz` | no | per-action authorization; can override recording config via `RecordObligation` |
| `nats` | no | JetStream KV for userstr cache; SSH failure event publishing |

## Authz integration

`authzcheck.go` wraps the authz gRPC service. When `authz.address` is set:

- `checkSSHAuthz` — evaluates shell, exec, sftp, and agent-forward actions; returns an error to deny
- `checkSessionAuthz` — evaluates session:start and returns a `RecordObligation` that overrides `server.recording.*` for that session

When authz is not configured both functions return nil/false and callers fall back to static config.

## gRPC control interface

`grpc.go` serves `sshproxy.v1.SSHProxyService` (proto + generated stubs live in the `common` module under `pkg/api/proto/sshproxy/v1` and `pkg/api/gen/go/sshproxy/v1`). It is built on `gapi.Server`, same as identity/provisioner/session, and is **opt-in**: it starts only when a port is set under the `grpc:` config block (`gapi.ServerConfig` — port, TLS, `authEnabled`, `allowed` callers). It is started/stopped by `Server.Start`/`Server.Stop` in the non-forking parent only; forking child processes never serve gRPC.

- `GetVersionInfo` — returns `common.v1.GetVersionInfoResponse` (version, commit_id, description) sourced from `SSHPROXY_VERSION`/`SSHPROXY_COMMIT`. Same RPC name/signature every other k8shell service exposes.

## Logging

zerolog, JSON by default. Pass `--logtext` for human-readable output. Logger names: `ssh-server`, `ssh-failures`. Log level is set via the logger package defaults; no config field.

## Forking mode

`server.forking: true` causes each accepted connection to be handled in a child process. The child receives the TCP socket on fd 3 and is invoked as:

```
./ssh-proxy --child --config config.yaml [--logtext]
```

Child processes do **not** share the parent's listener, NATS client, identity/session/provisioner clients, or gRPC server — they create their own (and never serve gRPC).

## Config defaults

| Field | Default |
|---|---|
| `server.SSHHandshakeTimeout` | 30 s |
| `server.maxDirectTCPIPConnections` | 15 |
| `server.sftpBinary` | `/usr/local/bin/sftp` |
| `server.port` | required — no default |

## Conventions

- All gRPC clients are constructed in `NewServer` (non-forking) or `HandleConnectionChildProcess` (forking child).
- Per-connection state lives in `Connection` (connection.go). Access via `Server.GetConnInfo(conn)`.
- Channel sequence numbers (`sh-`, `ex-`, `sf-`, `ux-` prefixes) are generated with `Connection.SeqNumber()`.
- User tokens are cached in a process-local map with 2-minute expiry skew (`connection.go: userTokenCache`).
- `userstr` parsing (`github.com/k8shell-io/common/pkg/userstr`) handles the `user@blueprint` SSH username format.
