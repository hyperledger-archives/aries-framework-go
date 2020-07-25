/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webnotifier

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const (
	preState  = "pre_state"
	postState = "post_state"
)

// Notifier represents a notification dispatcher.
type Notifier interface {
	Notify(topic string, message []byte) error
}

// Observer instance.
type Observer struct {
	notifier Notifier
}

// NewObserver returns observer.
func NewObserver(notifier Notifier) *Observer {
	return &Observer{notifier: notifier}
}

// RegisterAction registers action channel to observer events.
func (o *Observer) RegisterAction(topic string, ch <-chan service.DIDCommAction) {
	go func() {
		for action := range ch {
			o.notify(topic, toAction(action))
		}
	}()
}

// RegisterStateMsg registers state channel to observer events.
func (o *Observer) RegisterStateMsg(topic string, ch <-chan service.StateMsg) {
	go func() {
		for msg := range ch {
			o.notify(topic, toStateMsg(msg))
		}
	}()
}

func (o *Observer) notify(topic string, v interface{}) {
	src, err := json.Marshal(v)
	if err != nil {
		logger.Errorf("notify marshal: %s", err)
		return
	}

	err = o.notifier.Notify(topic, src)
	if err != nil {
		logger.Errorf("notify: %s", err)
	}
}

// StateMsg represents service.StateMsg.
type StateMsg struct {
	ProtocolName string                 `json:",omitempty"`
	Type         string                 `json:",omitempty"`
	StateID      string                 `json:",omitempty"`
	Message      service.DIDCommMsgMap  `json:",omitempty"`
	Properties   map[string]interface{} `json:",omitempty"`
}

func toStateMsg(e service.StateMsg) *StateMsg {
	stateMsg := &StateMsg{
		ProtocolName: e.ProtocolName,
		StateID:      e.StateID,
	}

	stateMsg.Type = preState
	if e.Type == service.PostState {
		stateMsg.Type = postState
	}

	if e.Msg != nil {
		stateMsg.Message = e.Msg.Clone()
	}

	if e.Properties != nil {
		stateMsg.Properties = e.Properties.All()
	}

	return stateMsg
}

// Action represents service.DIDCommAction.
type Action struct {
	ProtocolName string                 `json:",omitempty"`
	Message      service.DIDCommMsgMap  `json:",omitempty"`
	Properties   map[string]interface{} `json:",omitempty"`
}

func toAction(e service.DIDCommAction) *Action {
	action := &Action{
		ProtocolName: e.ProtocolName,
	}

	if e.Message != nil {
		action.Message = e.Message.Clone()
	}

	if e.Properties != nil {
		action.Properties = e.Properties.All()
	}

	return action
}
