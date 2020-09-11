/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/pkg/controller"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
)

// Aries is an implementation of AriesController which handles requests locally.
type Aries struct {
	framework *aries.Aries
	handlers  map[string]map[string]command.Exec
	notifiers map[string]api.Notifier
}

// NewAries returns a new Aries instance that contains handlers and an Aries framework instance.
func NewAries(opts *config.Options) (*Aries, error) {
	options, err := prepareFrameworkOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare framework options: %w", err)
	}

	framework, err := aries.New(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Aries framework: %w", err)
	}

	context, err := framework.Context()
	if err != nil {
		return nil, fmt.Errorf("failed to get Framework context: %w", err)
	}

	var controllerOpts []controller.Opt
	if opts.Notifier != nil {
		controllerOpts = append(controllerOpts, controller.WithNotifier(opts.Notifier))
	}

	commandHandlers, err := controller.GetCommandHandlers(context, controllerOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to get command handlers: %w", err)
	}

	handlers := make(map[string]map[string]command.Exec)
	populateHandlers(commandHandlers, handlers)

	notifiers := make(map[string]api.Notifier)

	return &Aries{framework, handlers, notifiers}, nil
}

func prepareFrameworkOptions(opts *config.Options) ([]aries.Option, error) {
	msgHandler := msghandler.NewRegistrar()

	var options []aries.Option
	options = append(options, aries.WithMessageServiceProvider(msgHandler))

	if opts.TransportReturnRoute != "" {
		options = append(options, aries.WithTransportReturnRoute(opts.TransportReturnRoute))
	}

	if opts.DBNamespace != "" {
		options = append(options, defaults.WithStorePath(opts.DBNamespace))
	} else {
		options = append(options, aries.WithStoreProvider(mem.NewProvider()))
	}

	for _, transport := range opts.OutboundTransport {
		switch transport {
		case "http":
			outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
			if err != nil {
				return nil, err
			}

			options = append(options, aries.WithOutboundTransports(outbound))
		case "ws":
			options = append(options, aries.WithOutboundTransports(ws.NewOutbound()))
		default:
			return nil, fmt.Errorf("unsupported transport : %s", transport)
		}
	}

	if len(opts.HTTPResolvers) > 0 {
		rsopts, err := getResolverOpts(opts.HTTPResolvers)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare http resolver opts : %w", err)
		}

		options = append(options, rsopts...)
	}

	return options, nil
}

func getResolverOpts(httpResolvers []string) ([]aries.Option, error) {
	var opts []aries.Option

	const numPartsResolverOption = 2

	if len(httpResolvers) > 0 {
		for _, httpResolver := range httpResolvers {
			r := strings.Split(httpResolver, "@")
			if len(r) != numPartsResolverOption {
				return nil, fmt.Errorf("invalid http resolver options found")
			}

			httpVDRI, err := httpbinding.New(r[1],
				httpbinding.WithAccept(func(method string) bool { return method == r[0] }))

			if err != nil {
				return nil, fmt.Errorf("failed to setup http resolver :  %w", err)
			}

			opts = append(opts, aries.WithVDRI(httpVDRI))
		}
	}

	return opts, nil
}

func populateHandlers(commands []command.Handler, pkgMap map[string]map[string]command.Exec) {
	for _, cmd := range commands {
		fnMap, ok := pkgMap[cmd.Name()]
		if !ok {
			fnMap = make(map[string]command.Exec)
		}

		fnMap[cmd.Method()] = cmd.Handle()
		pkgMap[cmd.Name()] = fnMap
	}
}

// RegisterNotifier associates a notifier to relevant topics.
// This is implemented by mobile apps and leverages notifiers from the SDK.
func (a *Aries) RegisterNotifier(n api.Notifier, topics string) error {
	/* ... */

	for _, topic := range strings.Split(topics, ",") {
		a.notifiers[topic] = n
		if err := n.Notify(topic, n.GetPayload()); err != nil {
			return fmt.Errorf("failed to register notifier to topic [%s]: %w", topic, err)
		}
	}

	/* ... */

	return nil
}

// GetIntroduceController returns an Introduce instance.
func (a *Aries) GetIntroduceController() (api.IntroduceController, error) {
	handlers, ok := a.handlers[introduce.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", introduce.CommandName)
	}

	return &Introduce{handlers: handlers}, nil
}

// GetVerifiableController returns a Verifiable instance.
func (a *Aries) GetVerifiableController() (api.VerifiableController, error) {
	handlers, ok := a.handlers[verifiable.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", verifiable.CommandName)
	}

	return &Verifiable{handlers: handlers}, nil
}

// GetDIDExchangeController returns a DIDExchange instance.
func (a *Aries) GetDIDExchangeController() (api.DIDExchangeController, error) {
	handlers, ok := a.handlers[didexchange.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", didexchange.CommandName)
	}

	return &DIDExchange{handlers: handlers}, nil
}

// GetIssueCredentialController returns an IssueCredential instance.
func (a *Aries) GetIssueCredentialController() (api.IssueCredentialController, error) {
	handlers, ok := a.handlers[issuecredential.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", issuecredential.CommandName)
	}

	return &IssueCredential{handlers: handlers}, nil
}

// GetPresentProofController returns an PresentProof instance.
func (a *Aries) GetPresentProofController() (api.PresentProofController, error) {
	handlers, ok := a.handlers[presentproof.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", presentproof.CommandName)
	}

	return &PresentProof{handlers: handlers}, nil
}

// GetVDRIController returns a VDRI instance.
func (a *Aries) GetVDRIController() (api.VDRIController, error) {
	handlers, ok := a.handlers[vdri.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", vdri.CommandName)
	}

	return &VDRI{handlers: handlers}, nil
}

// GetMediatorController returns a Mediator instance.
func (a *Aries) GetMediatorController() (api.MediatorController, error) {
	handlers, ok := a.handlers[mediator.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", mediator.CommandName)
	}

	return &Mediator{handlers: handlers}, nil
}

// GetMessagingController returns a Messaging instance.
func (a *Aries) GetMessagingController() (api.MessagingController, error) {
	handlers, ok := a.handlers[messaging.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", messaging.CommandName)
	}

	return &Messaging{handlers: handlers}, nil
}

// GetOutOfBandController returns a OutOfBand instance.
func (a *Aries) GetOutOfBandController() (api.OutOfBandController, error) {
	handlers, ok := a.handlers[outofband.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", outofband.CommandName)
	}

	return &OutOfBand{handlers: handlers}, nil
}

// GetKMSController returns a KMS instance.
func (a *Aries) GetKMSController() (api.KMSController, error) {
	handlers, ok := a.handlers[kms.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", kms.CommandName)
	}

	return &KMS{handlers: handlers}, nil
}
