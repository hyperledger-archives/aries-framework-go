/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
)

// MockIssueCredentialSvc mock issue credential service.
type MockIssueCredentialSvc struct {
	service.Action
	service.Message
	ProtocolName                   string
	HandleFunc                     func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc             func(msg service.DIDCommMsg, myDID, theirDID string) (string, error)
	AcceptFunc                     func(string) bool
	ActionsFunc                    func() ([]issuecredential.Action, error)
	ActionContinueFunc             func(string, ...issuecredential.Opt) error
	RegisterMsgEventHandle         func(chan<- service.StateMsg) error
	RegisterMsgEventErr            error
	UnregisterMsgEventHandle       func(chan<- service.StateMsg) error
	UnregisterMsgEventErr          error
	RegisterActionEventHandle      func(ch chan<- service.DIDCommAction) error
	RegisterActionEventHandleErr   error
	UnregisterActionEventHandle    func(ch chan<- service.DIDCommAction) error
	UnregisterActionEventHandleErr error
}

// Initialize service.
func (m *MockIssueCredentialSvc) Initialize(interface{}) error {
	return nil
}

// HandleInbound msg.
func (m *MockIssueCredentialSvc) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// HandleOutbound msg.
func (m *MockIssueCredentialSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return "", nil
}

// Accept msg checks the msg type.
func (m *MockIssueCredentialSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// Name return service name.
func (m *MockIssueCredentialSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}

	return "issue-credential"
}

// Actions mock implementation of issue credential service actions interface.
func (m *MockIssueCredentialSvc) Actions() ([]issuecredential.Action, error) {
	if m.ActionsFunc != nil {
		return m.ActionsFunc()
	}

	return []issuecredential.Action{}, nil
}

// ActionContinue mock implementation of issue credential service action continue interface.
func (m *MockIssueCredentialSvc) ActionContinue(piID string, opt ...issuecredential.Opt) error {
	if m.ActionContinueFunc != nil {
		return m.ActionContinueFunc(piID, opt...)
	}

	return nil
}

// ActionStop mock implementation of issue credential service action stop interface.
func (m *MockIssueCredentialSvc) ActionStop(piID string, err error, opt ...issuecredential.Opt) error {
	return nil
}

// RegisterMsgEvent register message event.
func (m *MockIssueCredentialSvc) RegisterMsgEvent(ch chan<- service.StateMsg) error {
	if m.RegisterMsgEventErr != nil {
		return m.RegisterMsgEventErr
	}

	if m.RegisterMsgEventHandle != nil {
		return m.RegisterMsgEventHandle(ch)
	}

	return nil
}

// UnregisterMsgEvent unregister message event.
func (m *MockIssueCredentialSvc) UnregisterMsgEvent(ch chan<- service.StateMsg) error {
	if m.UnregisterMsgEventErr != nil {
		return m.UnregisterMsgEventErr
	}

	if m.UnregisterMsgEventHandle != nil {
		return m.UnregisterMsgEventHandle(ch)
	}

	return nil
}

// RegisterActionEvent mock implementation of issue credential service RegisterActionEvent.
func (m *MockIssueCredentialSvc) RegisterActionEvent(ch chan<- service.DIDCommAction) error {
	if m.RegisterActionEventHandleErr != nil {
		return m.RegisterActionEventHandleErr
	}

	if m.RegisterActionEventHandle != nil {
		return m.RegisterActionEventHandle(ch)
	}

	return nil
}

// UnregisterActionEvent mock implementation of issue credential service UnregisterActionEvent.
func (m *MockIssueCredentialSvc) UnregisterActionEvent(ch chan<- service.DIDCommAction) error {
	if m.UnregisterActionEventHandleErr != nil {
		return m.UnregisterActionEventHandleErr
	}

	if m.UnregisterActionEventHandle != nil {
		return m.UnregisterActionEventHandle(ch)
	}

	return nil
}
