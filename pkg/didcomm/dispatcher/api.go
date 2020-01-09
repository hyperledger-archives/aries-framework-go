/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// Service protocol service
type Service interface {
	service.Handler
	Accept(msgType string) bool
	Name() string
}

// MessageService is service for handling generic messages
// matching accept criteria
type MessageService interface {
	service.InboundHandler
	Accept(header *service.Header) bool
	Name() string
}

// MessageHandler maintains registered message services
// and it allows dynamic registration of message services
type MessageHandler interface {
	// Services returns list of available message services in this message handler
	Services() []MessageService
	// Register registers given message services to this message handler
	Register(msgSvcs ...MessageService) error
	// Unregister unregisters message service with given name from this message handler
	Unregister(name string) error
}

// Outbound interface
type Outbound interface {
	// Sends the message after packing with the sender key and recipient keys.
	Send(interface{}, string, *service.Destination) error

	// Sends the message after packing with the keys derived from DIDs.
	SendToDID(msg interface{}, myDID, theirDID string) error

	// Forward forwards the message without packing to the destination.
	Forward(interface{}, *service.Destination) error
}
