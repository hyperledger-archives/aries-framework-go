/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
)

// Context
type Context struct {
	DIDExchangeClients map[string]*didexchange.Client
	PublicDIDs         map[string]*did.Doc
	AgentCtx           map[string]*context.Provider
	Invitations        map[string]*didexchange.Invitation
	PostStatesFlag     map[string]map[string]chan bool
	ConnectionID       map[string]string
}

// NewContext create new Context
func NewContext() (*Context, error) {
	instance := Context{
		DIDExchangeClients: make(map[string]*didexchange.Client),
		Invitations:        make(map[string]*didexchange.Invitation),
		PublicDIDs:         make(map[string]*did.Doc),
		PostStatesFlag:     make(map[string]map[string]chan bool),
		ConnectionID:       make(map[string]string),
		AgentCtx:           make(map[string]*context.Provider),
	}
	return &instance, nil
}

// BeforeScenario execute code before bdd scenario
func (b *Context) BeforeScenario(scenarioOrScenarioOutline interface{}) {
}

// AfterScenario execute code after bdd scenario
func (b *Context) AfterScenario(interface{}, error) {
}
