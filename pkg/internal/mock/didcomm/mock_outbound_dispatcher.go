/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didcomm

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

// MockOutboundDispatcher mock outbound dispatcher
type MockOutboundDispatcher struct {
	SendErr error
}

// Send msg
func (m *MockOutboundDispatcher) Send(msg interface{}, des *dispatcher.Destination) error {
	return m.SendErr
}
