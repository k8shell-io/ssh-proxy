#!/usr/bin/env bash
# Hot-swaps a freshly built $HOME/<repo-name>/bin/<repo-name> into a running
# container without restarting it. Relies on the alpine runtime's while-loop
# entrypoint (see docker/${REPO_NAME}/Dockerfile): killing the child process
# leaves the `while true; do /app/<repo-name>; done` parent alive, which
# immediately respawns using whatever binary is now at /app/<repo-name>.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_NAME="$(basename -s .git "$(git -C "$SCRIPT_DIR" config --get remote.origin.url)")"
REPO_DIR="${HOME}/${REPO_NAME}"

BIN_NAME="$REPO_NAME"
LOCAL_BIN="${REPO_DIR}/bin/${BIN_NAME}"
CONTAINER_BIN="/app/${BIN_NAME}"

if [[ ! -f "$LOCAL_BIN" ]]; then
  echo "error: ${LOCAL_BIN} not found — run 'make build' first" >&2
  exit 1
fi

# Only the process the while-loop started: in forking mode each connection runs
# in a "--child" process whose parent is the main process, so skip any whose
# parent is itself ${BIN_NAME}.
CHILD_PIDS=()
for pid in $(pgrep -x "$BIN_NAME" || true); do
  ppid=$(ps -o ppid= -p "$pid" | tr -d ' ')
  [[ -n "$ppid" && "$(ps -o comm= -p "$ppid")" != "$BIN_NAME" ]] && CHILD_PIDS+=("$pid")
done
if [[ ${#CHILD_PIDS[@]} -eq 0 ]]; then
  echo "error: no running ${BIN_NAME} process found" >&2
  exit 1
elif [[ ${#CHILD_PIDS[@]} -gt 1 ]]; then
  echo "error: multiple ${BIN_NAME} processes found (${CHILD_PIDS[*]}) — expected exactly one" >&2
  exit 1
fi
CHILD_PID="${CHILD_PIDS[0]}"

PARENT_PID=$(ps -o ppid= -p "$CHILD_PID" | tr -d ' ')
if [[ -z "$PARENT_PID" ]]; then
  echo "error: could not determine parent pid of ${CHILD_PID}" >&2
  exit 1
fi

ROOT="/proc/${PARENT_PID}/root"
TARGET="${ROOT}${CONTAINER_BIN}"
TARGET_NEW="${TARGET}.new"

if ! sudo test -e "$ROOT"; then
  echo "error: ${ROOT} not accessible — is pid ${PARENT_PID} the loop's namespace root?" >&2
  exit 1
fi

echo "${BIN_NAME}: child=${CHILD_PID} parent(loop)=${PARENT_PID}"
echo "copying ${LOCAL_BIN} -> ${TARGET_NEW}"
sudo cp "$LOCAL_BIN" "$TARGET_NEW"

echo "installing: ${TARGET_NEW} -> ${TARGET}"
sudo mv "$TARGET_NEW" "$TARGET"

echo "killing pid ${CHILD_PID} to trigger respawn"
sudo kill "$CHILD_PID"

echo "done — loop (pid ${PARENT_PID}) should respawn ${CONTAINER_BIN} momentarily"
