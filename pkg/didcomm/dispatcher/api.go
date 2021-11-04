/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// ProtocolService is service interface for protocol services available in framework
// for matching acceptance criteria based on message type.
type ProtocolService interface {
	service.Handler
	Accept(msgType string) bool
	Name() string
	Initialize(interface{}) error
}

// MessageService is service for handling generic messages
// matching accept criteria based on message header.
type MessageService interface {
	service.InboundHandler
	Accept(msgType string, purpose []string) bool
	Name() string
}

// Outbound interface.
type Outbound interface {
	// Send the message after packing with the sender key and recipient keys.
	Send(interface{}, string, *service.Destination) error

	// SendToDID Sends the message after packing with the keys derived from DIDs.
	SendToDID(msg interface{}, myDID, theirDID string) error

	// Forward forwards the message without packing to the destination.
	Forward(interface{}, *service.Destination) error
}

// MessageTypeTarget represents a service message type mapping value to an OOB target action.
type MessageTypeTarget struct {
	MsgType string
	Target  string
}
