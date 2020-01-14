/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/common"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"
)

// MessageHandler maintains registered message services
// and it allows dynamic registration of message services
type MessageHandler interface {
	// Services returns list of available message services in this message handler
	Services() []dispatcher.MessageService
	// Register registers given message services to this message handler
	Register(msgSvcs ...dispatcher.MessageService) error
	// Unregister unregisters message service with given name from this message handler
	Unregister(name string) error
}

type allOpts struct {
	webhookURLs  []string
	defaultLabel string
	autoAccept   bool
	msgHandler   MessageHandler
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
func WithMessageHandler(handler MessageHandler) Opt {
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

	var allHandlers []operation.Handler

	// Add DID Exchange Rest Handlers
	exchange, err := didexchange.New(ctx, webhook.NewHTTPNotifier(restAPIOpts.webhookURLs), restAPIOpts.defaultLabel,
		restAPIOpts.autoAccept)
	if err != nil {
		return nil, err
	}

	// Add common Rest Handlers
	general := common.New(ctx)

	allHandlers = append(allHandlers, exchange.GetRESTHandlers()...)
	allHandlers = append(allHandlers, general.GetRESTHandlers()...)

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
