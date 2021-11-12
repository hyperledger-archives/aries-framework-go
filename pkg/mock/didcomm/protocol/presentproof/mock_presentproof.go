/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
)

// MockPresentProofSvc mock present proof service.
type MockPresentProofSvc struct {
	service.Action
	service.Message
	ProtocolName             string
	HandleFunc               func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc       func(msg service.DIDCommMsg, myDID, theirDID string) (string, error)
	AcceptFunc               func(string) bool
	ActionsFunc              func() ([]presentproof.Action, error)
	ActionContinueFunc       func(string, ...presentproof.Opt) error
	RegisterMsgEventHandle   func(chan<- service.StateMsg) error
	RegisterMsgEventErr      error
	UnregisterMsgEventHandle func(chan<- service.StateMsg) error
	UnregisterMsgEventErr    error
}

// Initialize service.
func (m *MockPresentProofSvc) Initialize(interface{}) error {
	return nil
}

// HandleInbound msg.
func (m *MockPresentProofSvc) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// HandleOutbound msg.
func (m *MockPresentProofSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return "", nil
}

// Accept msg checks the msg type.
func (m *MockPresentProofSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// Name return service name.
func (m *MockPresentProofSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}

	return "present-proof"
}

// Actions mock implementation of present proof service actions interface.
func (m *MockPresentProofSvc) Actions() ([]presentproof.Action, error) {
	if m.ActionsFunc != nil {
		return m.ActionsFunc()
	}

	return []presentproof.Action{}, nil
}

// ActionContinue mock implementation of present proof service action continue interface.
func (m *MockPresentProofSvc) ActionContinue(piID string, opt ...presentproof.Opt) error {
	if m.ActionContinueFunc != nil {
		return m.ActionContinueFunc(piID, opt...)
	}

	return nil
}

// ActionStop mock implementation of present proof service action stop interface.
func (m *MockPresentProofSvc) ActionStop(piID string, err error, opt ...presentproof.Opt) error {
	return nil
}

// RegisterMsgEvent register message event.
func (m *MockPresentProofSvc) RegisterMsgEvent(ch chan<- service.StateMsg) error {
	if m.RegisterMsgEventErr != nil {
		return m.RegisterMsgEventErr
	}

	if m.RegisterMsgEventHandle != nil {
		return m.RegisterMsgEventHandle(ch)
	}

	return nil
}

// UnregisterMsgEvent unregister message event.
func (m *MockPresentProofSvc) UnregisterMsgEvent(ch chan<- service.StateMsg) error {
	if m.UnregisterMsgEventErr != nil {
		return m.UnregisterMsgEventErr
	}

	if m.UnregisterMsgEventHandle != nil {
		return m.UnregisterMsgEventHandle(ch)
	}

	return nil
}
