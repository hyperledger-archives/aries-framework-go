/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

// StateMsgType state msg type.
type StateMsgType int

const (
	// PreState pre state.
	PreState StateMsgType = iota

	// PostState post state.
	PostState
)

// StateMsg is used in MsgEvent to pass the state details to the consumer. Refer service.Event.RegisterMsgEvent
// for more details.
type StateMsg struct {
	// Name of the protocol.
	//
	// Supported protocols
	//   - DID Exchange :  didexchange.DIDExchange
	ProtocolName string

	// type of the message (pre or post), refer service.StateMsgType
	Type StateMsgType

	// current state. Refer protocol RFC for possible states.
	StateID string

	// DIDComm message along with message type
	Msg DIDCommMsg

	// Properties contains value based on specific protocol. The consumers need to call the protocol client
	// functions to get the data.
	//
	// Clients function to retrieve data based on protocol.
	//   - DID Exchange :  didexchange.Event
	Properties EventProperties
}

// DIDCommAction message type to pass events in go channels.
type DIDCommAction struct {
	// Name of the protocol.
	//
	// Supported protocols
	//   - DID Exchange :  didexchange.DIDExchange
	ProtocolName string

	// DIDComm message
	Message DIDCommMsg

	// Continue function to be called by the consumer for further processing the message.
	Continue func(args interface{})

	// Stop invocation notifies the service that the consumer action event processing has failed or the consumer wants
	// to stop the processing.
	Stop func(err error)

	// Properties contains value based on specific protocol. The consumers need to call the protocol client
	// functions to get the data.
	//
	// Clients function to retrieve data based on protocol.
	//   - DID Exchange :  didexchange.EventProperties
	Properties EventProperties
}

// EventProperties type for event related data.
// NOTE: Properties always should be serializable.
type EventProperties interface {
	All() map[string]interface{}
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

// AutoExecuteActionEvent is a utility function to execute Action events automatically. The function requires
// a channel to be passed-in to listen to dispatcher.DIDCommAction and triggers the Continue function on the
// action event. This is a blocking function and use this function with a goroutine.
//
// Usage:
//  s := didexchange.New(....)
//	actionCh := make(chan dispatcher.DIDCommAction)
//	err = s.RegisterActionEvent(actionCh)
//	go service.AutoExecuteActionEvent(actionCh)
func AutoExecuteActionEvent(ch chan DIDCommAction) {
	for msg := range ch {
		msg.Continue(&Empty{})
	}
}

// Empty is used if there are no arguments to Continue.
type Empty struct{}
