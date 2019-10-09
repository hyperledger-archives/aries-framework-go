/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

// StateMsgType state msg type
type StateMsgType int

const (
	// PreState pre state
	PreState StateMsgType = iota
	// PostState post state
	PostState
)

// StateMsg msg
type StateMsg struct {
	Type    StateMsgType
	StateID string
	Msg     DIDCommMsg
	// Properties contains different values from different protocols
	Properties map[string]interface{}
}

// DIDCommAction message type to pass events in go channels.
type DIDCommAction struct {
	// DIDComm message
	Message DIDCommMsg
	// Continue function to be called by the consumer for further processing the message.
	Continue func()
	// Stop invocation notifies the service that the consumer action event processing has failed or the consumer wants
	// to stop the processing.
	Stop func(err error)
	// Properties contains different values from different protocols
	Properties map[string]interface{}
}

// Event event related apis.
type Event interface {
	// RegisterActionEvent on protocol messages. The events are triggered for incoming message types based on
	// the protocol service. The consumer need to invoke the callback to resume processing.
	// Only one channel can be registered for the action events. The function will throw error if a channel is already
	// registered.
	RegisterActionEvent(ch chan<- DIDCommAction) error

	// UnregisterActionEvent on protocol messages. Refer RegisterActionEvent().
	UnregisterActionEvent(ch chan<- DIDCommAction) error

	// RegisterMsgEvent on protocol messages. The message events are triggered for incoming messages. Service
	// will not expect any callback on these events unlike Action event.
	RegisterMsgEvent(ch chan<- StateMsg) error

	// UnregisterMsgEvent on protocol messages. Refer RegisterMsgEvent().
	UnregisterMsgEvent(ch chan<- StateMsg) error
}
