/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange"
)

// New returns new controller REST API instance.
//
// TODO: Allow customized operations.
func New(ctx *context.Provider) (*Controller, error) {
	var allHandlers []operation.Handler

	// Add DID Exchange Rest Handlers
	exchange, err := didexchange.New(ctx)
	if err != nil {
		return nil, err
	}

	allHandlers = append(allHandlers, exchange.GetRESTHandlers()...)

	return &Controller{handlers: allHandlers}, nil
}

// Controller contains handlers for controller REST API
type Controller struct {
	handlers []operation.Handler
}

// GetOperations returns all controller REST API endpoints
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
