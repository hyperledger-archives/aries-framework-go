/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/connection"
	didexchangecmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	introducecmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	issuecredentialcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	ldcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	routercmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	messagingcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	outofbandcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	outofbandv2cmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofbandv2"
	presentproofcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	vcwalletcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	vdrcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	connectionrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/connection"
	didexchangerest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
	introducerest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	issuecredentialrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/issuecredential"
	kmsrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/kms"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/mediator"
	messagingrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
	outofbandrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/outofband"
	outofbandv2rest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/outofbandv2"
	presentproofrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/rfc0593"
	vcwalletrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vcwallet"
	vdrrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdr"
	verifiablerest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	ldsvc "github.com/hyperledger/aries-framework-go/pkg/ld"
)

// HTTPClient represents an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type allOpts struct {
	webhookURLs        []string
	defaultLabel       string
	autoAccept         bool
	autoExecuteRFC0593 bool
	msgHandler         command.MessageHandler
	notifier           command.Notifier
	walletConf         *vcwalletcmd.Config
	httpClient         HTTPClient
	ldService          ldsvc.Service
}

const wsPath = "/ws"

// Opt represents a controller option.
type Opt func(opts *allOpts)

// WithWebhookURLs is an option for setting up a webhook dispatcher which will notify clients of events.
func WithWebhookURLs(webhookURLs ...string) Opt {
	return func(opts *allOpts) {
		opts.webhookURLs = webhookURLs
	}
}

// WithNotifier is an option for setting up a notifier which will notify clients of events.
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

// WithAutoExecuteRFC0593 enables RFC0593.
func WithAutoExecuteRFC0593(autoExecute bool) Opt {
	return func(opts *allOpts) {
		opts.autoExecuteRFC0593 = autoExecute
	}
}

// WithMessageHandler is an option allowing for the message handler to be set.
func WithMessageHandler(handler command.MessageHandler) Opt {
	return func(opts *allOpts) {
		opts.msgHandler = handler
	}
}

// WithWalletConfiguration is an option for customizing vcwallet controller.
func WithWalletConfiguration(conf *vcwalletcmd.Config) Opt {
	return func(opts *allOpts) {
		opts.walletConf = conf
	}
}

// WithHTTPClient is an option for setting up a custom HTTP client.
func WithHTTPClient(client HTTPClient) Opt {
	return func(opts *allOpts) {
		opts.httpClient = client
	}
}

// WithLDService is an option for setting up a custom JSON-LD service.
func WithLDService(svc ldsvc.Service) Opt {
	return func(opts *allOpts) {
		opts.ldService = svc
	}
}

// GetRESTHandlers returns all REST handlers provided by controller.
func GetRESTHandlers(ctx *context.Provider, opts ...Opt) ([]rest.Handler, error) { // nolint: funlen,gocyclo
	restAPIOpts := &allOpts{
		httpClient: http.DefaultClient,
		ldService:  ldsvc.New(ctx),
	}

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

	// VDR REST operation
	vdrOp, err := vdrrest.New(ctx)
	if err != nil {
		return nil, err
	}

	// messaging REST operation
	messagingOp, err := messagingrest.New(ctx, restAPIOpts.msgHandler, notifier)
	if err != nil {
		return nil, err
	}

	// route REST operation
	routeOp, err := mediator.New(ctx, restAPIOpts.autoAccept)
	if err != nil {
		return nil, err
	}

	// verifiable command operation
	verifiablecmd, err := verifiablerest.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create verifiable rest command : %w", err)
	}

	var issuecredentialOp *issuecredentialrest.Operation

	if restAPIOpts.autoExecuteRFC0593 {
		issuecredentialOp, err = issuecredentialrest.New(ctx, notifier, ctx)
	} else {
		issuecredentialOp, err = issuecredentialrest.New(ctx, notifier, nil)
	}
	// issuecredential REST operation
	if err != nil {
		return nil, fmt.Errorf("create issue-credential rest command : %w", err)
	}

	rfc0593Op := rfc0593.New(ctx)

	// presentproof REST operation
	presentproofOp, err := presentproofrest.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("create present-proof rest command : %w", err)
	}

	// introduce REST operation
	introduceOp, err := introducerest.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("create introduce rest command : %w", err)
	}

	// outofband REST operation
	outofbandOp, err := outofbandrest.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("create outofband rest command : %w", err)
	}

	// outofband REST operation
	outofbandV2Op, err := outofbandv2rest.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create outofband/2.0 rest command : %w", err)
	}

	// kms command operation
	kmscmd := kmsrest.New(ctx)

	// vc wallet command controller
	wallet := vcwalletrest.New(ctx, restAPIOpts.walletConf)

	// JSON-LD REST operation
	ldOp := ldrest.New(restAPIOpts.ldService, ldrest.WithHTTPClient(restAPIOpts.httpClient))

	connOp, err := connectionrest.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create connection rest command : %w", err)
	}

	// creat handlers from all operations
	var allHandlers []rest.Handler
	allHandlers = append(allHandlers, exchangeOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, vdrOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, messagingOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, routeOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, verifiablecmd.GetRESTHandlers()...)
	allHandlers = append(allHandlers, issuecredentialOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, rfc0593Op.GetRESTHandlers()...)
	allHandlers = append(allHandlers, presentproofOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, introduceOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, outofbandOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, outofbandV2Op.GetRESTHandlers()...)
	allHandlers = append(allHandlers, kmscmd.GetRESTHandlers()...)
	allHandlers = append(allHandlers, wallet.GetRESTHandlers()...)
	allHandlers = append(allHandlers, ldOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, connOp.GetRESTHandlers()...)

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
func GetCommandHandlers(ctx *context.Provider, opts ...Opt) ([]command.Handler, error) { // nolint: funlen,gocyclo
	cmdOpts := &allOpts{
		httpClient: http.DefaultClient,
		ldService:  ldsvc.New(ctx),
	}

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

	// VDR command operation
	vcmd, err := vdrcmd.New(ctx)
	if err != nil {
		return nil, err
	}

	// messaging command operation
	msgcmd, err := messagingcmd.New(ctx, cmdOpts.msgHandler, notifier)
	if err != nil {
		return nil, err
	}

	// route command operation
	routecmd, err := routercmd.New(ctx, cmdOpts.autoAccept)
	if err != nil {
		return nil, err
	}

	// verifiable command operation
	verifiablecmd, err := verifiable.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create verifiable command : %w", err)
	}

	// issuecredential command operation
	issuecredential, err := issuecredentialcmd.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("create issue-credential command : %w", err)
	}

	// presentproof command operation
	presentproof, err := presentproofcmd.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("create present-proof command : %w", err)
	}

	// introduce command operation
	introduce, err := introducecmd.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("create introduce command : %w", err)
	}

	// outofband command operation
	outofband, err := outofbandcmd.New(ctx, notifier)
	if err != nil {
		return nil, fmt.Errorf("create outofband command : %w", err)
	}

	// outofbandv2 command operation
	outofbandv2, err := outofbandv2cmd.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create outofbandv2 command : %w", err)
	}

	// kms command operation
	kmscmd := kms.New(ctx)

	// connection command operation
	conncmd, err := connection.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create connection command : %w", err)
	}

	// vc wallet command controller
	wallet := vcwalletcmd.New(ctx, cmdOpts.walletConf)

	// JSON-LD command operation
	ldCmd := ldcmd.New(cmdOpts.ldService, ldcmd.WithHTTPClient(cmdOpts.httpClient))

	var allHandlers []command.Handler
	allHandlers = append(allHandlers, didexcmd.GetHandlers()...)
	allHandlers = append(allHandlers, vcmd.GetHandlers()...)
	allHandlers = append(allHandlers, msgcmd.GetHandlers()...)
	allHandlers = append(allHandlers, routecmd.GetHandlers()...)
	allHandlers = append(allHandlers, verifiablecmd.GetHandlers()...)
	allHandlers = append(allHandlers, kmscmd.GetHandlers()...)
	allHandlers = append(allHandlers, issuecredential.GetHandlers()...)
	allHandlers = append(allHandlers, presentproof.GetHandlers()...)
	allHandlers = append(allHandlers, introduce.GetHandlers()...)
	allHandlers = append(allHandlers, outofband.GetHandlers()...)
	allHandlers = append(allHandlers, outofbandv2.GetHandlers()...)
	allHandlers = append(allHandlers, conncmd.GetHandlers()...)
	allHandlers = append(allHandlers, wallet.GetHandlers()...)
	allHandlers = append(allHandlers, ldCmd.GetHandlers()...)

	return allHandlers, nil
}
