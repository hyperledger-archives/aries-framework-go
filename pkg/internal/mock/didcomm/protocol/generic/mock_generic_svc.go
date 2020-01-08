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

// MockGenericSvc is mock generic service
type MockGenericSvc struct {
	HandleFunc func(*service.DIDCommMsg) (string, error)
	AcceptFunc func(header *service.Header) bool
}

// HandleInbound msg
func (m *MockGenericSvc) HandleInbound(msg *service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// Accept msg checks the msg type
func (m *MockGenericSvc) Accept(header *service.Header) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(header)
	}

	return true
}
