/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"context"
	"strings"
	"sync"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	bddcontext "github.com/hyperledger/aries-framework-go/pkg/framework/context"
)

var logger = log.New("aries-framework/tests/context")

// BDDContext is a global context shared between different test suites in bddtests.
type BDDContext struct {
	OutOfBandClients   map[string]*outofband.Client
	OutOfBandV2Clients map[string]*outofbandv2.Client
	DIDExchangeClients map[string]*didexchange.Client
	RouteClients       map[string]*mediator.Client
	RouteCallbacks     map[string]chan interface{}
	PublicDIDDocs      map[string]*did.Doc
	PublicKeys         map[string]*jwk.JWK
	PublicEncKeys      map[string][]byte // TODO: PublicEndKeys values are never set.
	KeyHandles         map[string]interface{}
	PublicDIDs         map[string]string
	PeerDIDs           map[string]string
	Agents             map[string]*aries.Aries
	AgentCtx           map[string]*bddcontext.Provider
	MessageRegistrar   map[string]*msghandler.Registrar
	Messengers         map[string]service.Messenger
	Args               map[string]string
	ConnectionIDs      map[string]map[string]string
	controllerURLs     map[string]string
	webhookURLs        map[string]string
	webSocketConns     map[string]*websocket.Conn
	webSocketData      sync.Map
	lock               sync.RWMutex
}

// NewBDDContext create new BDDContext.
func NewBDDContext() *BDDContext {
	return &BDDContext{
		OutOfBandClients:   make(map[string]*outofband.Client),
		OutOfBandV2Clients: make(map[string]*outofbandv2.Client),
		DIDExchangeClients: make(map[string]*didexchange.Client),
		RouteClients:       make(map[string]*mediator.Client),
		RouteCallbacks:     make(map[string]chan interface{}),
		PublicDIDDocs:      make(map[string]*did.Doc),
		PublicKeys:         make(map[string]*jwk.JWK),
		KeyHandles:         make(map[string]interface{}),
		PublicDIDs:         make(map[string]string),
		PeerDIDs:           make(map[string]string),
		Agents:             make(map[string]*aries.Aries),
		AgentCtx:           make(map[string]*bddcontext.Provider),
		MessageRegistrar:   make(map[string]*msghandler.Registrar),
		Messengers:         make(map[string]service.Messenger),
		Args:               make(map[string]string),
		ConnectionIDs:      make(map[string]map[string]string),
		controllerURLs:     make(map[string]string),
		webhookURLs:        make(map[string]string),
		webSocketConns:     make(map[string]*websocket.Conn),
	}
}

// Destroy BDD context.
func (b *BDDContext) Destroy() {
	// close all websocket connections
	for agentID, conn := range b.webSocketConns {
		err := conn.Close(websocket.StatusNormalClosure, "bddtests destroy context")
		if err != nil {
			logger.Warnf("failed to close websocket connection for [%s] : %v", agentID, err)
		}
	}

	for _, agent := range b.Agents {
		if err := agent.Close(); err != nil {
			logger.Warnf("failed to teardown aries framework : %s", err.Error())
		}
	}
}

// DeleteSDKAgent deletes an SDK agent, clearing all of its BDDContext data.
func (b *BDDContext) DeleteSDKAgent(agentName string) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if conn, ok := b.webSocketConns[agentName]; ok {
		err := conn.Close(websocket.StatusNormalClosure, "bddtests destroy context")
		if err != nil {
			logger.Warnf("failed to close websocket connection for [%s] : %v", agentName, err)
		}

		delete(b.webSocketConns, agentName)
	}

	if agent, ok := b.Agents[agentName]; ok {
		if err := agent.Close(); err != nil {
			logger.Warnf("failed to teardown aries framework : %s", err.Error())
		}

		delete(b.Agents, agentName)
	}

	delete(b.OutOfBandClients, agentName)
	delete(b.OutOfBandV2Clients, agentName)
	delete(b.DIDExchangeClients, agentName)
	delete(b.RouteClients, agentName)
	delete(b.RouteCallbacks, agentName)
	delete(b.PublicDIDDocs, agentName)
	delete(b.PublicKeys, agentName)
	delete(b.PublicEncKeys, agentName)
	delete(b.KeyHandles, agentName)
	delete(b.PublicDIDs, agentName)
	delete(b.PeerDIDs, agentName)
	delete(b.Messengers, agentName)
	delete(b.ConnectionIDs, agentName)
	delete(b.AgentCtx, agentName)
}

// RegisterWebhookURL registers given url to agent id for webhook.
func (b *BDDContext) RegisterWebhookURL(agentID, url string) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.webhookURLs[agentID] = url
}

// GetWebhookURL returns webhook url registered for given agent id.
func (b *BDDContext) GetWebhookURL(agentID string) (string, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	url, ok := b.webhookURLs[agentID]

	return url, ok
}

// RegisterControllerURL registers given url to agent id for controller.
func (b *BDDContext) RegisterControllerURL(agentID, url string) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.controllerURLs[agentID] = url
}

// GetControllerURL returns controller url registered for given agent id.
func (b *BDDContext) GetControllerURL(agentID string) (string, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	url, ok := b.controllerURLs[agentID]

	return url, ok
}

// Incoming represents WebSocket event message.
type Incoming struct {
	ID      string                `json:"id"`
	Topic   string                `json:"topic"`
	Message service.DIDCommMsgMap `json:"message"`
}

// RegisterWebSocketConn registers given websocket connection to agent id for web notifications.
func (b *BDDContext) RegisterWebSocketConn(agentID string, conn *websocket.Conn) {
	b.lock.Lock()
	defer b.lock.Unlock()

	const maxCapacity = 100

	b.webSocketConns[agentID] = conn

	stream := make(chan *Incoming, maxCapacity)
	b.webSocketData.LoadOrStore(agentID, stream)

	go func() {
		for {
			var incoming *Incoming

			err := wsjson.Read(context.Background(), conn, &incoming)
			if err == nil {
				stream <- incoming

				continue
			}

			if strings.Contains(err.Error(), "bddtests destroy context") {
				return
			}

			logger.Errorf("failed to get topics for agent '%s' : %v", agentID, err)
		}
	}()
}

// GetConnectionID gets the connection ID for agent's connection to target, or the empty string if there is none.
func (b *BDDContext) GetConnectionID(agent, target string) string {
	idMap, ok := b.ConnectionIDs[agent]
	if !ok {
		return ""
	}

	return idMap[target]
}

// SaveConnectionID sets the connection ID for agent's connection to target.
func (b *BDDContext) SaveConnectionID(agent, target, connID string) {
	if _, ok := b.ConnectionIDs[agent]; !ok {
		b.ConnectionIDs[agent] = make(map[string]string)
	}

	b.ConnectionIDs[agent][target] = connID
}

// OwnerOfDID helper function for finding an agent name that has a given DID within the bdd context.
func (b *BDDContext) OwnerOfDID(didStr string) string {
	for agent, pubDID := range b.PublicDIDs {
		if pubDID == didStr {
			return agent
		}
	}

	for agent, peerDID := range b.PeerDIDs {
		if peerDID == didStr {
			return agent
		}
	}

	for agent, pubDoc := range b.PublicDIDDocs {
		if pubDoc == nil {
			continue
		}

		if pubDoc.ID == didStr {
			return agent
		}
	}

	return ""
}

// ReadFromWebSocket reads from WebSocket.
func (b *BDDContext) ReadFromWebSocket(agentID string) <-chan *Incoming {
	stream, ok := b.webSocketData.Load(agentID)
	if !ok {
		return nil
	}

	return stream.(chan *Incoming)
}

// GetWebSocketConn returns websocket connection for given agent ID for web notifications.
func (b *BDDContext) GetWebSocketConn(agentID string) (*websocket.Conn, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	conn, ok := b.webSocketConns[agentID]

	return conn, ok
}
