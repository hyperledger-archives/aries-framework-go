/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

// MockDIDExchangeSvc mock did exchange service
type MockDIDExchangeSvc struct {
	HandleErr   error
	AcceptValue bool
}

// Handle msg
func (m *MockDIDExchangeSvc) Handle(msg dispatcher.DIDCommMsg) error {
	return m.HandleErr
}

// Accept msg checks the msg type
func (m *MockDIDExchangeSvc) Accept(msgType string) bool {
	return m.AcceptValue
}

// Name return service name
func (m *MockDIDExchangeSvc) Name() string {
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
func (m *MockDIDExchangeSvc) RegisterMsgEvent(ch chan<- dispatcher.DIDCommMsg) error {
	return nil
}

// UnregisterMsgEvent unregister message event.
func (m *MockDIDExchangeSvc) UnregisterMsgEvent(ch chan<- dispatcher.DIDCommMsg) error {
	return nil
}
