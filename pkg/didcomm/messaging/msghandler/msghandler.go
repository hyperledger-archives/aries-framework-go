/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

// Package msghandler dynamically maintains the list of registered message services.
//
// In addition to returning list of available message services as a message service provider implementation,
// this message handler also provides register/unregister functionality which can be used to add/remove
// message services from already running agent.
//
// (RFC Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0351-purpose-decorator/README.md)
//
package msghandler

import (
	"fmt"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
)

const (
	errAlreadyRegistered = "registration failed, message service with name `%s` already registered"
	errNeverRegistered   = "failed to unregister, unable to find registered message service with name `%s`"
)

// NewRegistrar returns new message registrar instance.
func NewRegistrar() *Registrar {
	return &Registrar{}
}

// Registrar is message service provider implementation which maintains list of registered message service
// and also allows dynamic register/unregister of message services.
type Registrar struct {
	services []dispatcher.MessageService
	lock     sync.RWMutex
}

// Services returns list of message services registered to this handler.
func (m *Registrar) Services() []dispatcher.MessageService {
	m.lock.RLock()
	defer m.lock.RUnlock()

	svcs := make([]dispatcher.MessageService, len(m.services))
	copy(svcs, m.services)

	return svcs
}

// Register registers given message services to this handler,
// returns error in case of duplicate registration.
func (m *Registrar) Register(msgServices ...dispatcher.MessageService) error {
	if len(msgServices) == 0 {
		return nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	// if current list is empty, add all
	if len(m.services) == 0 {
		m.services = append(m.services, msgServices...)
		return nil
	}

	// if current list is not empty, then look for duplicates before adding
	for _, newMsgSvc := range msgServices {
		for _, existingSvc := range m.services {
			if existingSvc.Name() == newMsgSvc.Name() {
				return fmt.Errorf(errAlreadyRegistered, newMsgSvc.Name())
			}
		}
	}

	m.services = append(m.services, msgServices...)

	return nil
}

// Unregister unregisters message service with given name from this message handler,
// returns error if given message service doesn't exists.
func (m *Registrar) Unregister(name string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	index := -1

	for i, svc := range m.services {
		if svc.Name() == name {
			index = i

			break
		}
	}

	if index < 0 {
		return fmt.Errorf(errNeverRegistered, name)
	}

	m.services = append(m.services[:index], m.services[index+1:]...)

	return nil
}
