/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messenger

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
)

// Provider contains dependencies for the Messenger
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
}

// Messenger describes the messenger structure
type Messenger struct {
	dispatcher dispatcher.Outbound
}

// NewMessenger returns a new instance of the Messenger
func NewMessenger(ctx Provider) *Messenger {
	return &Messenger{
		dispatcher: ctx.OutboundDispatcher(),
	}
}

// HandleInbound handles all inbound messages
// function behavior is flexible and can be modified by providing options
func (*Messenger) HandleInbound(msg service.DIDCommMsgMap, myDID, theirDID string) error {
	return nil
}

// Send sends the message by starting a new thread.
func (m *Messenger) Send(msg service.DIDCommMsgMap, myDID, theirDID string) error {
	return m.dispatcher.SendToDID(msg, myDID, theirDID)
}

// ReplyTo replies to the message by given msgID.
func (*Messenger) ReplyTo(msgID string, msg service.DIDCommMsgMap) error {
	return errors.New("does not implemented yet")
}

// ReplyToNested sends the message by starting a new thread.
func (*Messenger) ReplyToNested(threadID string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
	return errors.New("does not implemented yet")
}
