/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
)

// MockMessagePickupSvc mock messagepickup service.
type MockMessagePickupSvc struct {
	service.DIDComm
	ProtocolName       string
	StatusRequestErr   error
	StatusRequestFunc  func(connectionID string) (*messagepickup.Status, error)
	BatchPickupErr     error
	BatchPickupFunc    func(connectionID string, size int) (int, error)
	HandleInboundFunc  func(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error)
	HandleOutboundFunc func(_ service.DIDCommMsg, _, _ string) (string, error)
	AddMessageFunc     func(message []byte, theirDID string) error
	AddMessageErr      error
	AcceptFunc         func(msgType string) bool
	NoopErr            error
	NoopFunc           func(connectionID string) error
}

// Initialize service.
func (m *MockMessagePickupSvc) Initialize(interface{}) error {
	return nil
}

// Name return service name.
func (m *MockMessagePickupSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}

	return "messagepickup"
}

// StatusRequest perform StatusRequest.
func (m *MockMessagePickupSvc) StatusRequest(connectionID string) (*messagepickup.Status, error) {
	if m.StatusRequestErr != nil {
		return nil, m.StatusRequestErr
	}

	if m.StatusRequestFunc != nil {
		return m.StatusRequestFunc(connectionID)
	}

	return nil, nil
}

// BatchPickup perform BatchPickup.
func (m *MockMessagePickupSvc) BatchPickup(connectionID string, size int) (int, error) {
	if m.BatchPickupErr != nil {
		return 0, m.BatchPickupErr
	}

	if m.BatchPickupFunc != nil {
		return m.BatchPickupFunc(connectionID, size)
	}

	return 0, nil
}

// HandleInbound msg.
func (m *MockMessagePickupSvc) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	if m.HandleInboundFunc != nil {
		return m.HandleInboundFunc(msg, ctx)
	}

	return "", nil
}

// Accept msg checks the msg type.
func (m *MockMessagePickupSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// AddMessage perform AddMessage.
func (m *MockMessagePickupSvc) AddMessage(message []byte, theirDID string) error {
	if m.AddMessageErr != nil {
		return m.AddMessageErr
	}

	if m.AddMessageFunc != nil {
		return m.AddMessageFunc(message, theirDID)
	}

	return nil
}

// Noop perform Noop.
func (m *MockMessagePickupSvc) Noop(connectionID string) error {
	if m.NoopErr != nil {
		return m.NoopErr
	}

	if m.NoopFunc != nil {
		return m.NoopFunc(connectionID)
	}

	return nil
}
