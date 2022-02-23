/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/notifier"
	storageWrapper "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/storage"
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	ldcommand "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-agent-mobile/wrappers/command")

// Aries is an implementation of AriesController which handles requests locally.
type Aries struct {
	framework     *aries.Aries
	handlers      map[string]map[string]command.Exec
	notifications <-chan notifier.NotificationPayload
	mutex         sync.RWMutex
	subscribers   map[string]map[string][]api.Handler
}

// NewAries returns a new Aries instance that contains handlers and an Aries framework instance.
func NewAries(opts *config.Options) (*Aries, error) {
	opts.MsgHandler = msghandler.NewRegistrar()

	options, err := prepareFrameworkOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare framework options: %w", err)
	}

	framework, err := aries.New(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Aries framework: %w", err)
	}

	ctx, err := framework.Context()
	if err != nil {
		return nil, fmt.Errorf("failed to get Framework context: %w", err)
	}

	notifications := make(chan notifier.NotificationPayload)

	commandHandlers, err := controller.GetCommandHandlers(ctx,
		controller.WithNotifier(notifier.NewNotifier(notifications)),
		controller.WithAutoAccept(opts.AutoAccept),
		controller.WithMessageHandler(opts.MsgHandler),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get command handlers: %w", err)
	}

	handlers := make(map[string]map[string]command.Exec)
	populateHandlers(commandHandlers, handlers)

	a := &Aries{
		framework:     framework,
		handlers:      handlers,
		notifications: notifications,
		subscribers:   make(map[string]map[string][]api.Handler),
	}

	go a.startNotificationListener()

	return a, nil
}

func prepareFrameworkOptions(opts *config.Options) ([]aries.Option, error) {
	var options []aries.Option
	options = append(options, aries.WithMessageServiceProvider(opts.MsgHandler))

	if opts.TransportReturnRoute != "" {
		options = append(options, aries.WithTransportReturnRoute(opts.TransportReturnRoute))
	}

	var storageProvider storage.Provider
	if opts.Storage != nil {
		storageProvider = storageWrapper.New(opts.Storage)
	} else {
		storageProvider = mem.NewProvider()
	}

	options = append(options, aries.WithStoreProvider(storageProvider))

	for _, transport := range opts.OutboundTransport {
		otOpts, err := getOutBoundTransportOpts(transport, opts.WebsocketReadLimit)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare outbound transport opts : %w", err)
		}

		options = append(options, otOpts...)
	}

	if len(opts.HTTPResolvers) > 0 {
		rsOpts, err := getResolverOpts(opts.HTTPResolvers)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare http resolver opts : %w", err)
		}

		options = append(options, rsOpts...)
	}

	if opts.DocumentLoader != nil {
		options = append(options, aries.WithJSONLDDocumentLoader(opts.DocumentLoader))
	} else {
		dlOpts, err := getDocumentLoaderOpts(storageProvider, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare document loader opts : %w", err)
		}

		options = append(options, dlOpts...)
	}

	return options, nil
}

func getOutBoundTransportOpts(transport string, websocketReadLimit int64) ([]aries.Option, error) {
	var opts []aries.Option

	switch transport {
	case "http":
		outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
		if err != nil {
			return nil, err
		}

		opts = append(opts, aries.WithOutboundTransports(outbound))
	case "ws":
		var outboundOpts []ws.OutboundClientOpt

		if websocketReadLimit > 0 {
			outboundOpts = append(outboundOpts, ws.WithOutboundReadLimit(websocketReadLimit))
		}

		opts = append(opts, aries.WithOutboundTransports(ws.NewOutbound(outboundOpts...)))
	default:
		return nil, fmt.Errorf("unsupported transport : %s", transport)
	}

	return opts, nil
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

			httpVDR, err := httpbinding.New(r[1],
				httpbinding.WithAccept(func(method string) bool { return method == r[0] }))
			if err != nil {
				return nil, fmt.Errorf("failed to setup http resolver :  %w", err)
			}

			opts = append(opts, aries.WithVDR(httpVDR))
		}
	}

	return opts, nil
}

func createJSONLdContext(storageProvider storage.Provider) (*context.Provider, error) {
	contextStore, err := ldstore.NewContextStore(cachedstore.NewProvider(storageProvider, mem.NewProvider()))
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ctx, err := context.New(
		context.WithStorageProvider(storageProvider),
		context.WithJSONLDContextStore(contextStore),
		context.WithJSONLDRemoteProviderStore(remoteProviderStore),
	)
	if err != nil {
		return nil, fmt.Errorf("context creation failed: %w", err)
	}

	return ctx, nil
}

func getDocumentLoaderOpts(storageProvider storage.Provider, options *config.Options) ([]aries.Option, error) {
	var opts []aries.Option

	ctx, err := createJSONLdContext(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare json ld context : %w", err)
	}

	var documentLoader *ld.DocumentLoader

	if options.LoadRemoteDocuments {
		remoteDocumentLoader := jsonld.NewDefaultDocumentLoader(http.DefaultClient)
		documentLoader, err = ld.NewDocumentLoader(ctx, ld.WithRemoteDocumentLoader(remoteDocumentLoader))
	} else {
		documentLoader, err = ld.NewDocumentLoader(ctx)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to prepare document loader opts : %w", err)
	}

	opts = append(opts, aries.WithJSONLDDocumentLoader(documentLoader))

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

func (a *Aries) startNotificationListener() {
	// listens for notifications
	for notification := range a.notifications {
		a.mutex.RLock()
		// gets all handlers that were subscribed for the topic
		for _, handlers := range a.subscribers[notification.Topic] {
			// send the payload to the subscribers
			for _, handler := range handlers {
				if err := handler.Handle(notification.Topic, notification.Raw); err != nil {
					logger.Errorf("notification listener: %v", err)
				}
			}
		}
		a.mutex.RUnlock()
	}
}

// RegisterHandler registers a handler to process incoming notifications from the framework.
// Handler is implemented by mobile apps.
func (a *Aries) RegisterHandler(h api.Handler, topics string) string {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	id := uuid.New().String()

	for _, topic := range strings.Split(topics, ",") {
		if a.subscribers[topic] == nil {
			a.subscribers[topic] = map[string][]api.Handler{}
		}

		a.subscribers[topic][id] = append(a.subscribers[topic][id], h)
	}

	return id
}

// UnregisterHandler unregisters a handler by given id.
func (a *Aries) UnregisterHandler(id string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	for topic := range a.subscribers {
		for key := range a.subscribers[topic] {
			if key == id {
				delete(a.subscribers[topic], id)
			}
		}
	}
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

// GetVDRController returns a VDR instance.
func (a *Aries) GetVDRController() (api.VDRController, error) {
	handlers, ok := a.handlers[vdr.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", vdr.CommandName)
	}

	return &VDR{handlers: handlers}, nil
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

// GetOutOfBandV2Controller returns a OutOfBandV2 instance.
func (a *Aries) GetOutOfBandV2Controller() (api.OutOfBandV2Controller, error) {
	handlers, ok := a.handlers[outofbandv2.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", outofbandv2.CommandName)
	}

	return &OutOfBandV2{handlers: handlers}, nil
}

// GetKMSController returns a KMS instance.
func (a *Aries) GetKMSController() (api.KMSController, error) {
	handlers, ok := a.handlers[kms.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", kms.CommandName)
	}

	return &KMS{handlers: handlers}, nil
}

// GetLDController returns an LD instance.
func (a *Aries) GetLDController() (api.LDController, error) {
	handlers, ok := a.handlers[ldcommand.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", ldcommand.CommandName)
	}

	return &LD{handlers: handlers}, nil
}

// GetVCWalletController returns a VCWalletController instance.
func (a *Aries) GetVCWalletController() (api.VCWalletController, error) {
	handlers, ok := a.handlers[vcwallet.CommandName]
	if !ok {
		return nil, fmt.Errorf("no handlers found for controller [%s]", vcwallet.CommandName)
	}

	return &VCWallet{handlers: handlers}, nil
}
