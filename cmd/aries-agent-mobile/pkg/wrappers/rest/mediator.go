/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
)

// Mediator contains necessary fields to support its operations.
type Mediator struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// Register registers the agent with the router.
func (m *Mediator) Register(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, mediator.RegisterCommandMethod)
}

// Unregister unregisters the agent with the router.
func (m *Mediator) Unregister(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, mediator.UnregisterCommandMethod)
}

// Connections returns router`s connections.
func (m *Mediator) Connections(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, mediator.GetConnectionsCommandMethod)
}

// Reconnect sends noop message to given mediator connection to re-establish network connection.
func (m *Mediator) Reconnect(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, mediator.ReconnectCommandMethod)
}

// ReconnectAll sends noop message to all mediator connections to re-establish a network connections.
func (m *Mediator) ReconnectAll(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, mediator.ReconnectAllCommandMethod)
}

// Status returns details about pending messages for given connection.
func (m *Mediator) Status(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, mediator.StatusCommandMethod)
}

// BatchPickup dispatches pending messages for given connection.
func (m *Mediator) BatchPickup(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, mediator.BatchPickupCommandMethod)
}

func (m *Mediator) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        m.URL,
		token:      m.Token,
		httpClient: m.httpClient,
		endpoint:   m.endpoints[endpoint],
		request:    request,
	})
}
