/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

// MockOutbound mock outbound dispatcher
type MockOutbound struct {
	SendErr error
}

// Send msg
func (m *MockOutbound) Send(msg interface{}, senderVerKey string, des *dispatcher.Destination) error {
	return m.SendErr
}
