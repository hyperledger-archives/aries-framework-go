/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

// TODO https://github.com/hyperledger/aries-framework-go/issues/342 - refactor the pkg, currently contains dispatcher,
//  messages and events fuctionalities. (need to avoid cyclical dependecy)
import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// Service protocol service
type Service interface {
	Handle(msg DIDCommMsg) error
	Accept(msgType string) bool
	Name() string
}

// DIDCommMsg did comm msg
type DIDCommMsg struct {
	// Outbound indicates the direction of this DIDComm message:
	//   - outgoing (to another agent)
	//   - incoming (from another agent)
	Outbound bool
	Type     string
	Payload  []byte
	// TODO : might need refactor as per the issue-226
	OutboundDestination *Destination
}

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
}

// Destination provides the recipientKeys, routingKeys, and serviceEndpoint populated from Invitation
type Destination struct {
	RecipientKeys   []string
	ServiceEndpoint string
	RoutingKeys     []string
}

// Outbound interface
type Outbound interface {
	Send(interface{}, string, *Destination) error
}

// Provider interface for outbound ctx
type Provider interface {
	PackWallet() wallet.Pack
	OutboundTransports() []transport.OutboundTransport
}

// OutboundCreator method to create new outbound dispatcher service
type OutboundCreator func(prov Provider) (Outbound, error)

// DIDCommAction message type to pass events in go channels.
type DIDCommAction struct {
	// DIDComm message
	Message DIDCommMsg
	// Callback function to be called by the consumer for further processing the message.
	Callback Callback
}

// DIDCommCallback message type to pass service callback in go channels.
type DIDCommCallback struct {
	// Set the value in case of any error while processing the DIDComm message event by the consumer.
	Err error
}

// Callback type to pass service callbacks.
type Callback func(DIDCommCallback)

// Event related apis.
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

// DIDCommService defines service APIs.
type DIDCommService interface {
	// dispatcher service
	Service

	// event service
	Event
}
