/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	didexchangecmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	messagingcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	routercmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/route"
	vdricmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	didexchangerest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
	kmsrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/kms"
	messagingrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/route"
	vdrirest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdri"
	verifiablerest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
)

type allOpts struct {
	webhookURLs  []string
	defaultLabel string
	autoAccept   bool
	msgHandler   command.MessageHandler
	notifier     command.Notifier
}

const wsPath = "/ws"

// Opt represents a controller option.
type Opt func(opts *allOpts)

// WithWebhookURLs is an option for setting up a webhook dispatcher which will notify clients of events
func WithWebhookURLs(webhookURLs ...string) Opt {
	return func(opts *allOpts) {
		opts.webhookURLs = webhookURLs
	}
}

// WithNotifier is an option for setting up a notifier which will notify clients of events
func WithNotifier(notifier command.Notifier) Opt {
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

	notifier := restAPIOpts.notifier
	if notifier == nil {
		notifier = webnotifier.New(wsPath, restAPIOpts.webhookURLs)
	}

	// DID Exchange REST operation
	exchangeOp, err := didexchangerest.New(ctx, notifier, restAPIOpts.defaultLabel,
		restAPIOpts.autoAccept)
	if err != nil {
		return nil, err
	}

	// VDRI REST operation
	vdriOp := vdrirest.New(ctx)

	// messaging REST operation
	messagingOp, err := messagingrest.New(ctx, restAPIOpts.msgHandler, notifier)
	if err != nil {
		return nil, err
	}

	// route REST operation
	routeOp, err := route.New(ctx)
	if err != nil {
		return nil, err
	}

	// verifiable command operation
	verifiablecmd, err := verifiablerest.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create verifiable rest command : %w", err)
	}

	// kms command operation
	kmscmd := kmsrest.New(ctx)

	// creat handlers from all operations
	var allHandlers []rest.Handler
	allHandlers = append(allHandlers, exchangeOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, vdriOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, messagingOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, routeOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, verifiablecmd.GetRESTHandlers()...)
	allHandlers = append(allHandlers, kmscmd.GetRESTHandlers()...)

	nhp, ok := notifier.(handlerProvider)
	if ok {
		allHandlers = append(allHandlers, nhp.GetRESTHandlers()...)
	}

	return allHandlers, nil
}

type handlerProvider interface {
	GetRESTHandlers() []rest.Handler
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
		notifier = webnotifier.New(wsPath, cmdOpts.webhookURLs)
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

	// verifiable command operation
	verifiablecmd, err := verifiable.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create verifiable command : %w", err)
	}

	// kms command operation
	kmscmd := kms.New(ctx)

	var allHandlers []command.Handler
	allHandlers = append(allHandlers, didexcmd.GetHandlers()...)
	allHandlers = append(allHandlers, vcmd.GetHandlers()...)
	allHandlers = append(allHandlers, msgcmd.GetHandlers()...)
	allHandlers = append(allHandlers, routecmd.GetHandlers()...)
	allHandlers = append(allHandlers, verifiablecmd.GetHandlers()...)
	allHandlers = append(allHandlers, kmscmd.GetHandlers()...)

	return allHandlers, nil
}
