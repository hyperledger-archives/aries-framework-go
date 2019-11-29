/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didcomm

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"

// MockOutboundTransport mock outbound transport structure
type MockOutboundTransport struct {
	ExpectedResponse string
	SendErr          error
	AcceptValue      bool
}

// NewMockOutboundTransport new MockOutboundTransport instance
func NewMockOutboundTransport(expectedResponse string) *MockOutboundTransport {
	return &MockOutboundTransport{ExpectedResponse: expectedResponse}
}

// Send implementation of MockOutboundTransport.Send api
func (transport *MockOutboundTransport) Send(data []byte, destination *service.Destination) (string, error) {
	return transport.ExpectedResponse, transport.SendErr
}

// Accept url
func (transport *MockOutboundTransport) Accept(url string) bool {
	return transport.AcceptValue
}
