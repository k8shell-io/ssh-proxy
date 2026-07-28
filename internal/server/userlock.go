// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	natsc "github.com/k8shell-io/common/pkg/nats"
)

// userLockWatcherRetryInterval is how long to wait before retrying
// subscription setup, e.g. when the locked-users bucket's underlying stream
// doesn't exist yet because api-server hasn't created it.
const userLockWatcherRetryInterval = 10 * time.Second

// startUserLockWatcher subscribes to account lock/unlock events published by
// api-server and force-closes every live SSH connection for a user as soon
// as their account is locked. Unlocking is a no-op here: it does not
// reconnect anyone, the user simply logs in again normally on their next
// attempt. It blocks until s.ctx is canceled, so callers should run it in a
// goroutine.
//
// The durable consumer name is unique per process, not just per replica:
// in forking mode each connection is handled by its own child process, each
// with its own local connection state, so every process that can hold live
// connections must see every lock event. A durable name shared across
// subscribers would instead load-balance events between them, so any single
// subscriber would only observe some lock events instead of all of them.
func (s *Server) startUserLockWatcher() {
	if s.nats == nil {
		return
	}

	durable := fmt.Sprintf("ssh-proxy-%s-%d", GetProxyID(), os.Getpid())

	for {
		if s.ctx.Err() != nil {
			return
		}

		sub, err := s.nats.NewKVSubscriber(natsc.LOCKED_USERS_BUCKET, durable, natsc.KVSubscriberOptions{})
		if err == nil {
			err = sub.StartPull(s.ctx, s.handleUserLockEvent)
		}

		if s.ctx.Err() != nil {
			return
		}
		if err != nil {
			s.log.Warn().Msgf("locked-users subscription unavailable, retrying in %s: %v",
				userLockWatcherRetryInterval, err)
		}

		select {
		case <-s.ctx.Done():
			return
		case <-time.After(userLockWatcherRetryInterval):
		}
	}
}

// handleUserLockEvent processes a single locked-users KV event.
func (s *Server) handleUserLockEvent(_ context.Context, ev *natsc.KVEvent) error {
	// Deletes/purges of the key carry no value; there is nothing to act on.
	if len(ev.Value) == 0 {
		return nil
	}

	var state natsc.UserLockState
	if err := json.Unmarshal(ev.Value, &state); err != nil {
		return fmt.Errorf("failed to decode lock state for user %s: %w", ev.Key, err)
	}

	if state.Locked {
		closeAllSSHConnectionsForUser(ev.Key)
	}
	return nil
}
