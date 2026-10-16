// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"time"

	natsc "github.com/k8shell-io/common/pkg/nats"
)

// userLockWatcherRetryInterval is how long to wait before retrying
// subscription setup, e.g. while the NATS connection is not established.
const userLockWatcherRetryInterval = 10 * time.Second

// startUserLockWatcher starts watching account lock/unlock events published
// by api-server and force-closes every live SSH connection for a user as
// soon as their account is locked. Unlocking is a no-op here: it does not
// reconnect anyone, the user simply logs in again normally on their next
// attempt. The watcher runs until s.ctx is canceled; Stop waits for it.
//
// It uses a core NATS subscription rather than a JetStream consumer. In
// forking mode every accepted connection runs in its own child process, and
// each must see every lock event; a per-process durable consumer would leave
// one consumer per connection on the server until its InactiveThreshold
// expired. A core subscription keeps no server-side state. Events published
// while disconnected are missed, which is acceptable because the lock is
// also checked at login.
func (s *Server) startUserLockWatcher() {
	if s.nats == nil {
		return
	}
	s.wg.Add(1)
	go s.runUserLockWatcher()
}

func (s *Server) runUserLockWatcher() {
	defer s.wg.Done()
	for {
		sub, err := s.nats.SubscribeKVChanges(natsc.LOCKED_USERS_BUCKET, s.handleUserLockEvent)
		if err == nil {
			<-s.ctx.Done()
			_ = sub.Unsubscribe()
			return
		}
		s.log.Warn().Msgf("locked-users subscription unavailable, retrying in %s: %v",
			userLockWatcherRetryInterval, err)

		select {
		case <-s.ctx.Done():
			return
		case <-time.After(userLockWatcherRetryInterval):
		}
	}
}

// handleUserLockEvent processes a single locked-users KV event.
func (s *Server) handleUserLockEvent(ev *natsc.KVEvent) {
	// Deletes/purges of the key carry no value; there is nothing to act on.
	if len(ev.Value) == 0 {
		return
	}

	var state natsc.UserLockState
	if err := json.Unmarshal(ev.Value, &state); err != nil {
		s.log.Warn().Msgf("failed to decode lock state for user %s: %v", ev.Key, err)
		return
	}

	if state.Locked {
		closeAllSSHConnectionsForUser(ev.Key)
	}
}
