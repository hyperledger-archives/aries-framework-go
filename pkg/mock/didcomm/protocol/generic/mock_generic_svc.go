/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package generic

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// NewCustomMockMessageSvc returns new custom mock message service.
func NewCustomMockMessageSvc(typeVal, name string) *MockMessageSvc {
	return &MockMessageSvc{
		HandleFunc: func(*service.DIDCommMsg) (string, error) {
			return "", nil
		},
		AcceptFunc: func(msgType string, purpose []string) bool {
			return typeVal == msgType
		},
		NameVal: name,
	}
}

// MockMessageSvc is mock generic service.
type MockMessageSvc struct {
	HandleFunc func(*service.DIDCommMsg) (string, error)
	AcceptFunc func(msgType string, purpose []string) bool
	NameVal    string
}

// Initialize service.
func (m *MockMessageSvc) Initialize(interface{}) error {
	return nil
}

// HandleInbound msg.
func (m *MockMessageSvc) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(&msg)
	}

	return uuid.New().String(), nil
}

// Accept msg checks the msg type.
func (m *MockMessageSvc) Accept(msgType string, purpose []string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType, purpose)
	}

	return true
}

// Name name of message service.
func (m *MockMessageSvc) Name() string {
	return m.NameVal
}
