/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
)

// LD contains necessary fields to support its operations.
type LD struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// AddContexts adds JSON-LD contexts to the underlying storage.
func (c *LD) AddContexts(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return c.createRespEnvelope(request, ld.AddContextsCommandMethod)
}

// AddRemoteProvider adds remote provider and JSON-LD contexts from that provider.
func (c *LD) AddRemoteProvider(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return c.createRespEnvelope(request, ld.AddRemoteProviderCommandMethod)
}

// RefreshRemoteProvider updates contexts from the remote provider.
func (c *LD) RefreshRemoteProvider(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return c.createRespEnvelope(request, ld.RefreshRemoteProviderCommandMethod)
}

// DeleteRemoteProvider deletes remote provider and contexts from that provider.
func (c *LD) DeleteRemoteProvider(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return c.createRespEnvelope(request, ld.DeleteRemoteProviderCommandMethod)
}

// GetAllRemoteProviders gets all remote providers.
func (c *LD) GetAllRemoteProviders(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return c.createRespEnvelope(request, ld.GetAllRemoteProvidersCommandMethod)
}

// RefreshAllRemoteProviders updates contexts from all remote providers.
func (c *LD) RefreshAllRemoteProviders(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return c.createRespEnvelope(request, ld.RefreshAllRemoteProvidersCommandMethod)
}

func (c *LD) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        c.URL,
		token:      c.Token,
		httpClient: c.httpClient,
		endpoint:   c.endpoints[endpoint],
		request:    request,
	})
}
