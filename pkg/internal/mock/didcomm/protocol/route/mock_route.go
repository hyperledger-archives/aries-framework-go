/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// MockRouteSvc mock route service
type MockRouteSvc struct {
	ProtocolName       string
	HandleFunc         func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc func(msg service.DIDCommMsg, myDID, theirDID string) error
	AcceptFunc         func(string) bool
	SendRequestFunc    func(myDID, theirDID string) (string, error)
}

// HandleInbound msg
func (m *MockRouteSvc) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// HandleOutbound msg
func (m *MockRouteSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) error {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return nil
}

// Accept msg checks the msg type
func (m *MockRouteSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// Name return service name
func (m *MockRouteSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}

	return "route"
}

// SendRequest send route request
func (m *MockRouteSvc) SendRequest(myDID, theirDID string) (string, error) {
	if m.SendRequestFunc != nil {
		return m.SendRequestFunc(myDID, theirDID)
	}

	return "", nil
}
