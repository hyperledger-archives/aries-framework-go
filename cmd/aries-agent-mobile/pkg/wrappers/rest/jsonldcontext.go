/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/jsonld/context"
)

// JSONLDContext contains necessary fields to support its operations.
type JSONLDContext struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// AddContext adds JSON-LD contexts to the underlying storage.
func (c *JSONLDContext) AddContext(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return c.createRespEnvelope(request, context.AddContextCommandMethod)
}

func (c *JSONLDContext) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        c.URL,
		token:      c.Token,
		httpClient: c.httpClient,
		endpoint:   c.endpoints[endpoint],
		request:    request,
	})
}
