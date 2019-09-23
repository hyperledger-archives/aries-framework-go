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
