/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

// MockDIDExchangeSvc mock did exchange service
type MockDIDExchangeSvc struct {
	ProtocolName        string
	HandleFunc          func(dispatcher.DIDCommMsg) error
	AcceptFunc          func(string) bool
	RegisterMsgEventErr error
}

// Handle msg
func (m *MockDIDExchangeSvc) Handle(msg dispatcher.DIDCommMsg) error {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}
	return nil
}

// Accept msg checks the msg type
func (m *MockDIDExchangeSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}
	return true
}

// Name return service name
func (m *MockDIDExchangeSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}
	return "didexchange"
}

// RegisterActionEvent register action event.
func (m *MockDIDExchangeSvc) RegisterActionEvent(ch chan<- dispatcher.DIDCommAction) error {
	return nil
}

// UnregisterActionEvent unregister action event.
func (m *MockDIDExchangeSvc) UnregisterActionEvent(ch chan<- dispatcher.DIDCommAction) error {
	return nil
}

// RegisterMsgEvent register message event.
func (m *MockDIDExchangeSvc) RegisterMsgEvent(ch chan<- dispatcher.StateMsg) error {
	if m.RegisterMsgEventErr != nil {
		return m.RegisterMsgEventErr
	}
	return nil
}

// UnregisterMsgEvent unregister message event.
func (m *MockDIDExchangeSvc) UnregisterMsgEvent(ch chan<- dispatcher.StateMsg) error {
	return nil
}
