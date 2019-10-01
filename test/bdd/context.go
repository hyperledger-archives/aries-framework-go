/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
)

// Context
type Context struct {
	DIDExchangeClients map[string]*didexchange.Client
	Invitations        map[string]*didexchangesvc.Invitation
}

// NewContext create new Context
func NewContext() (*Context, error) {
	instance := Context{DIDExchangeClients: make(map[string]*didexchange.Client),
		Invitations: make(map[string]*didexchangesvc.Invitation)}
	return &instance, nil
}

// BeforeScenario execute code before bdd scenario
func (b *Context) BeforeScenario(scenarioOrScenarioOutline interface{}) {

}

// AfterScenario execute code after bdd scenario
func (b *Context) AfterScenario(interface{}, error) {
}
