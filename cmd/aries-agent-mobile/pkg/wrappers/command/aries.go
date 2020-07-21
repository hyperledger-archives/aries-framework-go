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
	cmddidexch "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	cmdintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	cmdverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
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

	commandHandlers, err := controller.GetCommandHandlers(context)
	if err != nil {
		return nil, fmt.Errorf("failed to get command handlers: %w", err)
	}

	handlers := make(map[string]map[string]command.Exec)
	populateHandlers(commandHandlers, handlers)

	return &Aries{framework, handlers}, nil
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

// GetIntroduceController returns an Introduce instance
func (a *Aries) GetIntroduceController() (api.IntroduceController, error) {
	handlers, ok := a.handlers[cmdintroduce.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", cmdintroduce.CommandName)
	}

	return &Introduce{handlers: handlers}, nil
}

// GetVerifiableController returns a Verifiable instance
func (a *Aries) GetVerifiableController() (api.VerifiableController, error) {
	handlers, ok := a.handlers[cmdverifiable.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", cmdverifiable.CommandName)
	}

	return &Verifiable{handlers: handlers}, nil
}

// GetDIDExchangeController returns a DIDExchange instance
func (a *Aries) GetDIDExchangeController() (api.DIDExchangeController, error) {
	handlers, ok := a.handlers[cmddidexch.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", cmddidexch.CommandName)
	}

	return &DIDExchange{handlers: handlers}, nil
}
