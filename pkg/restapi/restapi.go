/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"
)

type allOpts struct {
	webhookURLs     []string
	invitationLabel string
}

// Opt represents a REST Api option.
type Opt func(opts *allOpts)

// WithWebhookURLs is an option for setting up a webhook dispatcher which will notify clients of events
func WithWebhookURLs(webhookURLs ...string) Opt {
	return func(opts *allOpts) {
		opts.webhookURLs = webhookURLs
	}
}

// WithInvitationLabel is an option allowing for the invitation label to be set.
func WithInvitationLabel(invitationLabel string) Opt {
	return func(opts *allOpts) {
		opts.invitationLabel = invitationLabel
	}
}

// New returns new controller REST API instance.
// TODO: Allow customized operations.
func New(ctx *context.Provider, opts ...Opt) (*Controller, error) {
	restAPIOpts := &allOpts{}
	// Apply options
	for _, opt := range opts {
		opt(restAPIOpts)
	}

	var allHandlers []operation.Handler

	// Add DID Exchange Rest Handlers
	exchange, err := didexchange.New(ctx, webhook.NewHTTPNotifier(restAPIOpts.webhookURLs), restAPIOpts.invitationLabel)
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
