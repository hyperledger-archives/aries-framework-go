/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
)

// Messaging contains necessary fields to support its operations.
type Messaging struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// RegisterService registers new message service to message handler registrar.
func (m *Messaging) RegisterService(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, messaging.RegisterMessageServiceCommandMethod)
}

// UnregisterService unregisters given message service handler registrar.
func (m *Messaging) UnregisterService(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, messaging.UnregisterMessageServiceCommandMethod)
}

// Services returns list of registered service names.
func (m *Messaging) Services(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, messaging.RegisteredServicesCommandMethod)
}

// Send sends a new message to destination provided.
func (m *Messaging) Send(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, messaging.SendNewMessageCommandMethod)
}

// Reply sends reply to existing message.
func (m *Messaging) Reply(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, messaging.SendReplyMessageCommandMethod)
}

// RegisterHTTPService registers new http over didcomm service to message handler registrar.
func (m *Messaging) RegisterHTTPService(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return m.createRespEnvelope(request, messaging.RegisterHTTPMessageServiceCommandMethod)
}

func (m *Messaging) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        m.URL,
		token:      m.Token,
		httpClient: m.httpClient,
		endpoint:   m.endpoints[endpoint],
		request:    request,
	})
}
