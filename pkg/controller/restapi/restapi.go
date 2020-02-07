/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/controller/restapi/operation/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/restapi/operation/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/restapi/operation/route"
	"github.com/hyperledger/aries-framework-go/pkg/controller/restapi/operation/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
)

type allOpts struct {
	webhookURLs  []string
	defaultLabel string
	autoAccept   bool
	msgHandler   command.MessageHandler
}

// Opt represents a REST Api option.
type Opt func(opts *allOpts)

// WithWebhookURLs is an option for setting up a webhook dispatcher which will notify clients of events
func WithWebhookURLs(webhookURLs ...string) Opt {
	return func(opts *allOpts) {
		opts.webhookURLs = webhookURLs
	}
}

// WithDefaultLabel is an option allowing for the defaultLabel to be set.
func WithDefaultLabel(defaultLabel string) Opt {
	return func(opts *allOpts) {
		opts.defaultLabel = defaultLabel
	}
}

// WithAutoAccept is an option allowing for the auto accept to be set.
func WithAutoAccept(autoAccept bool) Opt {
	return func(opts *allOpts) {
		opts.autoAccept = autoAccept
	}
}

// WithMessageHandler is an option allowing for the message handler to be set.
func WithMessageHandler(handler command.MessageHandler) Opt {
	return func(opts *allOpts) {
		opts.msgHandler = handler
	}
}

// New returns new controller REST API instance.
func New(ctx *context.Provider, opts ...Opt) (*Controller, error) {
	restAPIOpts := &allOpts{}
	// Apply options
	for _, opt := range opts {
		opt(restAPIOpts)
	}

	// DID Exchange REST operation
	exchangeOp, err := didexchange.New(ctx, webhook.NewHTTPNotifier(restAPIOpts.webhookURLs), restAPIOpts.defaultLabel,
		restAPIOpts.autoAccept)
	if err != nil {
		return nil, err
	}

	// VDRI REST operation
	vdriOp, err := vdri.New(ctx)
	if err != nil {
		return nil, err
	}

	// messaging REST operation
	messagingOp, err := messaging.New(ctx, restAPIOpts.msgHandler, webhook.NewHTTPNotifier(restAPIOpts.webhookURLs))
	if err != nil {
		return nil, err
	}

	// route REST operation
	routeOp, err := route.New(ctx)
	if err != nil {
		return nil, err
	}

	// creat handlers from all operations
	var allHandlers []operation.Handler
	allHandlers = append(allHandlers, exchangeOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, vdriOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, messagingOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, routeOp.GetRESTHandlers()...)

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
