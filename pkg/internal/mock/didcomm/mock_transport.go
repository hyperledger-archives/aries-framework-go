/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didcomm

import "errors"

// MockOutboundTransport mock outbound transport structure
type MockOutboundTransport struct {
	ExpectedResponse string
}

// NewMockOutboundTransport new MockOutboundTransport instance
func NewMockOutboundTransport(expectedResponse string) *MockOutboundTransport {
	return &MockOutboundTransport{ExpectedResponse: expectedResponse}
}

// Send implementation of MockOutboundTransport.Send api
func (transport *MockOutboundTransport) Send(data, destination string) (string, error) {
	if data == "" || destination == "" {
		return "", errors.New("data and destination are mandatory")
	}

	return transport.ExpectedResponse, nil
}
