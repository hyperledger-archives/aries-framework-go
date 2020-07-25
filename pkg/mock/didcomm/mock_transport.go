/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didcomm

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// MockOutboundTransport mock outbound transport structure.
type MockOutboundTransport struct {
	ExpectedResponse string
	SendErr          error
	AcceptValue      bool
}

// NewMockOutboundTransport new MockOutboundTransport instance.
func NewMockOutboundTransport(expectedResponse string) *MockOutboundTransport {
	return &MockOutboundTransport{ExpectedResponse: expectedResponse}
}

// Start starts the transport.
func (o *MockOutboundTransport) Start(prov transport.Provider) error {
	return nil
}

// Send implementation of MockOutboundTransport.Send api.
func (o *MockOutboundTransport) Send(data []byte, destination *service.Destination) (string, error) {
	return o.ExpectedResponse, o.SendErr
}

// AcceptRecipient checks if there is a connection for the list of recipient keys.
func (o *MockOutboundTransport) AcceptRecipient([]string) bool {
	return false
}

// Accept url.
func (o *MockOutboundTransport) Accept(url string) bool {
	return o.AcceptValue
}
