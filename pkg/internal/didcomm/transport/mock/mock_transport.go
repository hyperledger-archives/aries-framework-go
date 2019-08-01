/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mocktransport

import errors "golang.org/x/xerrors"

// OutboundTransport mock outbound transport structure
type OutboundTransport struct {
	ExpectedResponse string
}

// NewOutboundTransport new OutboundTransport instance
func NewOutboundTransport(expectedResponse string) *OutboundTransport {
	return &OutboundTransport{ExpectedResponse: expectedResponse}
}

// Send implementation of OutboundTransport.Send api
func (transport *OutboundTransport) Send(data string, destination string) (string, error) {
	if data == "" || destination == "" {
		return "", errors.New("Data or destination can't be empty")
	}

	return transport.ExpectedResponse, nil
}
