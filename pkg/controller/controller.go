/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	didexchangecmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	messagingcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	routercmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/route"
	vdricmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	didexchangerest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
	messagingrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/route"
	vdrirest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
)

type allOpts struct {
	webhookURLs  []string
	defaultLabel string
	autoAccept   bool
	msgHandler   command.MessageHandler
	notifier     webhook.Notifier
}

// Opt represents a controller option.
type Opt func(opts *allOpts)

// WithWebhookURLs is an option for setting up a webhook dispatcher which will notify clients of events
func WithWebhookURLs(webhookURLs ...string) Opt {
	return func(opts *allOpts) {
		opts.webhookURLs = webhookURLs
	}
}

// WithNotifier is an option for setting up a notifier which will notify clients of events
func WithNotifier(notifier webhook.Notifier) Opt {
	return func(opts *allOpts) {
		opts.notifier = notifier
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

// GetRESTHandlers returns all REST handlers provided by controller.
func GetRESTHandlers(ctx *context.Provider, opts ...Opt) ([]rest.Handler, error) {
	restAPIOpts := &allOpts{}
	// Apply options
	for _, opt := range opts {
		opt(restAPIOpts)
	}

	// DID Exchange REST operation
	exchangeOp, err := didexchangerest.New(ctx, webhook.NewHTTPNotifier(restAPIOpts.webhookURLs), restAPIOpts.defaultLabel,
		restAPIOpts.autoAccept)
	if err != nil {
		return nil, err
	}

	// VDRI REST operation
	vdriOp := vdrirest.New(ctx)

	// messaging REST operation
	messagingOp, err := messagingrest.New(ctx, restAPIOpts.msgHandler, webhook.NewHTTPNotifier(restAPIOpts.webhookURLs))
	if err != nil {
		return nil, err
	}

	// route REST operation
	routeOp, err := route.New(ctx)
	if err != nil {
		return nil, err
	}

	// creat handlers from all operations
	var allHandlers []rest.Handler
	allHandlers = append(allHandlers, exchangeOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, vdriOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, messagingOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, routeOp.GetRESTHandlers()...)

	return allHandlers, nil
}

// GetCommandHandlers returns all command handlers provided by controller.
func GetCommandHandlers(ctx *context.Provider, opts ...Opt) ([]command.Handler, error) {
	cmdOpts := &allOpts{}
	// Apply options
	for _, opt := range opts {
		opt(cmdOpts)
	}

	notifier := cmdOpts.notifier
	if notifier == nil {
		notifier = webhook.NewHTTPNotifier(cmdOpts.webhookURLs)
	}

	// did exchange command operation
	didexcmd, err := didexchangecmd.New(ctx, notifier, cmdOpts.defaultLabel,
		cmdOpts.autoAccept)
	if err != nil {
		return nil, fmt.Errorf("failed initialized didexchange command: %w", err)
	}

	// VDRI command operation
	vcmd := vdricmd.New(ctx)

	// messaging command operation
	msgcmd, err := messagingcmd.New(ctx, cmdOpts.msgHandler, notifier)
	if err != nil {
		return nil, err
	}

	// route command operation
	routecmd, err := routercmd.New(ctx)
	if err != nil {
		return nil, err
	}

	var allHandlers []command.Handler
	allHandlers = append(allHandlers, didexcmd.GetHandlers()...)
	allHandlers = append(allHandlers, vcmd.GetHandlers()...)
	allHandlers = append(allHandlers, msgcmd.GetHandlers()...)
	allHandlers = append(allHandlers, routecmd.GetHandlers()...)

	return allHandlers, nil
}
