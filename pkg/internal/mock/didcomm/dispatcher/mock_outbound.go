/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// MockOutbound mock outbound dispatcher
type MockOutbound struct {
	ValidateSend    func(msg interface{}, senderVerKey string, des *service.Destination) error
	ValidateForward func(msg interface{}, des *service.Destination) error
	SendErr         error
}

// Send msg
func (m *MockOutbound) Send(msg interface{}, senderVerKey string, des *service.Destination) error {
	if m.ValidateSend != nil {
		return m.ValidateSend(msg, senderVerKey, des)
	}

	return m.SendErr
}

// SendToDID msg
func (m *MockOutbound) SendToDID(msg interface{}, myDID, theirDID string) error {
	return nil
}

// Forward msg
func (m *MockOutbound) Forward(msg interface{}, des *service.Destination) error {
	if m.ValidateForward != nil {
		return m.ValidateForward(msg, des)
	}

	return nil
}
