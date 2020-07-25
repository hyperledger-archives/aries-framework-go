/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"

// MockMessenger mock implementation of messenger.
type MockMessenger struct {
	ErrReplyTo           error
	ErrReplyToNested     error
	ErrSend              error
	ErrSendToDestination error
}

// ReplyTo mock messenger reply to.
func (m *MockMessenger) ReplyTo(msgID string, msg service.DIDCommMsgMap) error {
	if m.ErrReplyTo != nil {
		return m.ErrReplyTo
	}

	return nil
}

// Send mock messenger Send.
func (m *MockMessenger) Send(msg service.DIDCommMsgMap, myDID, theirDID string) error {
	if m.ErrSend != nil {
		return m.ErrSend
	}

	return nil
}

// ReplyToNested mock messenger reply to nested.
func (m *MockMessenger) ReplyToNested(threadID string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
	if m.ErrReplyToNested != nil {
		return m.ErrReplyToNested
	}

	return nil
}

// SendToDestination mock messenger SendToDestination.
func (m *MockMessenger) SendToDestination(msg service.DIDCommMsgMap, sender string,
	destination *service.Destination) error {
	if m.ErrSendToDestination != nil {
		return m.ErrSendToDestination
	}

	return nil
}
