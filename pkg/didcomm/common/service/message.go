/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import "sync"

// Message thread-safe message register structure.
type Message struct {
	mu     sync.RWMutex
	events []chan<- StateMsg
}

// MsgEvents returns event message channels.
func (m *Message) MsgEvents() []chan<- StateMsg {
	m.mu.RLock()
	events := append(m.events[:0:0], m.events...)
	m.mu.RUnlock()

	return events
}

// RegisterMsgEvent on protocol messages. The message events are triggered for incoming messages. Event
// will not expect any callback on these events unlike Action events.
func (m *Message) RegisterMsgEvent(ch chan<- StateMsg) error {
	if ch == nil {
		return ErrNilChannel
	}

	m.mu.Lock()
	m.events = append(m.events, ch)
	m.mu.Unlock()

	return nil
}

// UnregisterMsgEvent on protocol messages. Refer RegisterMsgEvent().
func (m *Message) UnregisterMsgEvent(ch chan<- StateMsg) error {
	m.mu.Lock()
	for i := 0; i < len(m.events); i++ {
		if m.events[i] == ch {
			m.events = append(m.events[:i], m.events[i+1:]...)
			i--
		}
	}
	m.mu.Unlock()

	return nil
}
