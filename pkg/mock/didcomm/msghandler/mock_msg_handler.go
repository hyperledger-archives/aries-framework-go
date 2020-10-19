/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package msghandler

import (
	"fmt"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
)

const errNeverRegistered = "failed to unregister, unable to find registered message service with name `%s`"

// NewMockMsgServiceProvider returns new custom mock message handler.
func NewMockMsgServiceProvider() *MockMsgSvcProvider {
	return &MockMsgSvcProvider{svcs: []dispatcher.MessageService{}}
}

// MockMsgSvcProvider is mock message handler.
type MockMsgSvcProvider struct {
	svcs          []dispatcher.MessageService
	RegisterErr   error
	UnregisterErr error
	lock          sync.RWMutex
}

// Services returns message services registered to this mock message handler.
func (m *MockMsgSvcProvider) Services() []dispatcher.MessageService {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return m.svcs
}

// Register registers given message services to this mock message handler.
func (m *MockMsgSvcProvider) Register(msgSvcs ...dispatcher.MessageService) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.svcs = append(m.svcs, msgSvcs...)

	return m.RegisterErr
}

// Unregister unregisters given message services from this mock message handler.
func (m *MockMsgSvcProvider) Unregister(name string) error {
	if m.UnregisterErr != nil {
		return m.UnregisterErr
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	index := -1

	for i, msgSvc := range m.svcs {
		if msgSvc.Name() == name {
			index = i

			break
		}
	}

	if index < 0 {
		return fmt.Errorf(errNeverRegistered, name)
	}

	m.svcs = append(m.svcs[:index], m.svcs[index+1:]...)

	return nil
}
