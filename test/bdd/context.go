/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	didexchange2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
)

// Context
type Context struct {
	DIDExchangeClients map[string]*didexchange.Client
	Invitations        map[string]*didexchange2.Invitation
	PostStatesFlag     map[string]chan bool
}

// NewContext create new Context
func NewContext() (*Context, error) {
	instance := Context{DIDExchangeClients: make(map[string]*didexchange.Client),
		Invitations: make(map[string]*didexchange2.Invitation), PostStatesFlag: make(map[string]chan bool)}
	return &instance, nil
}

// BeforeScenario execute code before bdd scenario
func (b *Context) BeforeScenario(scenarioOrScenarioOutline interface{}) {

}

// AfterScenario execute code after bdd scenario
func (b *Context) AfterScenario(interface{}, error) {
}
