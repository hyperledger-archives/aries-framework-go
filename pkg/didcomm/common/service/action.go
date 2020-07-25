/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"sync"
)

// Action thread-safe action register structure.
type Action struct {
	mu    sync.RWMutex
	event chan<- DIDCommAction
}

// ActionEvent returns event action channel.
func (a *Action) ActionEvent() chan<- DIDCommAction {
	a.mu.RLock()
	e := a.event
	a.mu.RUnlock()

	return e
}

// RegisterActionEvent on protocol messages.
// The consumer need to invoke the callback to resume processing.
// Only one channel can be registered for the action events. The function will throw error if a channel is already
// registered.
func (a *Action) RegisterActionEvent(ch chan<- DIDCommAction) error {
	if ch == nil {
		return ErrNilChannel
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.event != nil {
		return ErrChannelRegistered
	}

	a.event = ch

	return nil
}

// UnregisterActionEvent on protocol messages. Refer RegisterActionEvent().
func (a *Action) UnregisterActionEvent(ch chan<- DIDCommAction) error {
	if ch == nil {
		return ErrNilChannel
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.event != ch {
		return ErrInvalidChannel
	}

	a.event = nil

	return nil
}
