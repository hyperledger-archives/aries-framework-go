/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
)

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	DIDExchangeClients map[string]*didexchange.Client
	PublicDIDs         map[string]*did.Doc
	AgentCtx           map[string]*context.Provider
	Args               map[string]string
	controllerURLs     map[string]string
	webhookURLs        map[string]string
	lock               sync.RWMutex
}

// NewBDDContext create new BDDContext
func NewBDDContext() (*BDDContext, error) {
	instance := BDDContext{
		DIDExchangeClients: make(map[string]*didexchange.Client),
		PublicDIDs:         make(map[string]*did.Doc),
		AgentCtx:           make(map[string]*context.Provider),
		Args:               make(map[string]string),
		controllerURLs:     make(map[string]string),
		webhookURLs:        make(map[string]string),
	}

	return &instance, nil
}

// BeforeScenario execute code before bdd scenario
func (b *BDDContext) BeforeScenario(scenarioOrScenarioOutline interface{}) {
}

// AfterScenario execute code after bdd scenario
func (b *BDDContext) AfterScenario(interface{}, error) {
}

// RegisterWebhookURL registers given url to agent id for webhook
func (b *BDDContext) RegisterWebhookURL(agentID, url string) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.webhookURLs[agentID] = url
}

// GetWebhookURL returns webhook url registered for given agent id
func (b *BDDContext) GetWebhookURL(agentID string) (string, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	url, ok := b.webhookURLs[agentID]

	return url, ok
}

// RegisterControllerURL registers given url to agent id for controller
func (b *BDDContext) RegisterControllerURL(agentID, url string) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.controllerURLs[agentID] = url
}

// GetControllerURL returns controller url registered for given agent id
func (b *BDDContext) GetControllerURL(agentID string) (string, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	url, ok := b.controllerURLs[agentID]

	return url, ok
}
