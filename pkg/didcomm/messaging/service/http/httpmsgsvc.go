/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package http

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const (
	// OverDIDCommSpec is http over DIDComm Spec value
	OverDIDCommSpec = "https://didcomm.org/http-over-didcomm/1.0/"

	// httpOverDIDComm is http over DIDComm message service name
	httpOverDIDComm = "http-over-didcomm"
)

// NewHTTPOverDIDComm creates new HTTP over DIDComm message service which serves
// incoming DIDComm message over HTTP.
func NewHTTPOverDIDComm() *OverDIDComm {
	return &OverDIDComm{httpOverDIDComm}
}

// OverDIDComm is message service which transports incoming DIDComm message over to
// intended http resource providers
type OverDIDComm struct {
	name string
}

// Name of HTTP over DIDComm message service
func (m *OverDIDComm) Name() string {
	return m.name
}

// Accept criteria for HTTP over DIDComm message service
// TODO purpose based acceptance criteria [Issue #1106]
func (m *OverDIDComm) Accept(msgType string, purpose []string) bool {
	return msgType == OverDIDCommSpec
}

// HandleInbound for HTTP over DIDComm message service
// TODO incoming DIDComm message to HTTP request[Issue #1106]
func (m *OverDIDComm) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	return "", fmt.Errorf("to be implemented")
}
