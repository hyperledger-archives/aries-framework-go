/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	remotecrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	aries "github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexchangebdd "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	bddldcontext "github.com/hyperledger/aries-framework-go/test/bdd/pkg/ldcontext"
)

const (
	dbPath = "./db"

	httpTransportProvider      = "http"
	webSocketTransportProvider = "websocket"
	sideTreeURL                = "${SIDETREE_URL}"
)

var logger = log.New("aries-framework/tests")

// SDKSteps contains steps for agent from client SDK.
type SDKSteps struct {
	bddContext           *context.BDDContext
	didExchangeSDKS      *didexchangebdd.SDKSteps
	newKeyType           kms.KeyType
	newKeyAgreementType  kms.KeyType
	newMediaTypeProfiles []string
	agentOpts            map[string][]createAgentOption
}

// NewSDKSteps returns new agent from client SDK.
func NewSDKSteps() *SDKSteps {
	return &SDKSteps{
		agentOpts: map[string][]createAgentOption{},
	}
}

// RegisterSteps registers agent steps.
func (a *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^options ""([^"]*)"" ""([^"]*)"" ""([^"]*)""$`, a.scenario)
	s.Step(`^all agents are using Media Type Profiles "([^"]*)"$`, a.useMediaTypeProfiles)
	s.Step(`^"([^"]*)" exchange DIDs V2 with "([^"]*)"$`, a.createConnectionV2)

	// leave these? replacing doesn't simplify.
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" `+
		`with http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`, a.CreateAgentWithHTTPDIDResolver)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with "([^"]*)" as the transport provider$`,
		a.CreateAgent)
	s.Step(`^"([^"]*)" edge agent is running with "([^"]*)" as the outbound transport provider `+
		`and "([^"]*)" as the transport return route option`, a.createEdgeAgentDIDCommV1)

	// new-style steps: set parameters, then initialize either an 'edge' or 'cloud' agent

	s.Step(`^"([^"]*)" is started with a "([^"]*)" DIDComm endpoint$`,
		a.initializeCloudAgent)
	s.Step(`^"([^"]*)" is started as an edge agent`,
		a.initializeEdgeAgent)

	s.Step(`^"([^"]*)" has a DIDComm endpoint at "([^"]*)" port "([^"]*)"$`,
		a.agentUsesInboundTransport) // omit this step to default to localhost random.
	s.Step(`^"([^"]*)" uses outbound transport "([^"]*)" and transport return route option "([^"]*)"$`,
		a.agentUsesEdgeTransport) // omit this step to default to websocket all.

	s.Step(`^"([^"]*)" auto-accepts present-proof messages$`,
		a.agentUsesAutoTrigger)
	s.Step(`^"([^"]*)" uses http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`,
		a.agentUsesHTTPResolver)
	s.Step(`^"([^"]*)" uses webkms with key server at "([^"]*)", using "([^"]*)" controller$`,
		a.agentUsesRemoteKMS)
	s.Step(`^"([^"]*)" uses a message registrar$`,
		a.agentUsesMessageRegistrar)
	s.Step(`^"([^"]*)" uses DIDComm v2$`,
		a.agentUsesDIDCommV2)
	s.Step(`^"([^"]*)" uses configured encryption parameters$`,
		a.agentUsesDynamicEnvParams)
}

func (a *SDKSteps) declareAgent(agentID string) error {
	a.agentOpts[agentID] = []createAgentOption{}

	return nil
}

func (a *SDKSteps) initializeCloudAgent(agentID, scheme string) error {
	return a.createAgentWithOptions(agentID, scheme, a.agentOpts[agentID]...)
}

func (a *SDKSteps) initializeEdgeAgent(agentID string) error {
	return a.createEdgeAgent(agentID, a.agentOpts[agentID]...)
}

func (a *SDKSteps) agentUsesInboundTransport(agent, host, port string) error {
	a.addAriesOption(agent, withHostPort(host, port))

	return nil
}

func (a *SDKSteps) agentUsesEdgeTransport(agent, transportType, returnRoute string) error {
	a.addAriesOption(agent, withEdgeTransport(transportType, returnRoute))

	return nil
}

func (a *SDKSteps) agentUsesAutoTrigger(agent string) error {
	a.addAriesOption(agent, withAutoTrigger(), withServiceMsgTypeTargets())

	return nil
}

func (a *SDKSteps) agentUsesHTTPResolver(agent string, endpointURL, acceptDidMethod string) error {
	a.addAriesOption(agent, a.withHTTPResolver(endpointURL, acceptDidMethod))

	return nil
}

func (a *SDKSteps) agentUsesRemoteKMS(agent string, kmsURL, controller string) error {
	a.addAriesOption(agent, withRemoteKMSCrypto(kmsURL, controller))

	return nil
}

func (a *SDKSteps) agentUsesMessageRegistrar(agent string) error {
	a.addAriesOption(agent, a.withRegistrar())

	return nil
}

func (a *SDKSteps) agentUsesServiceTypeTargets(agent string) error {
	a.addAriesOption(agent, withServiceMsgTypeTargets())

	return nil
}

func (a *SDKSteps) agentUsesDIDCommV2(agent string) error {
	a.addAriesOption(agent, withDIDCommV2())

	return nil
}

func (a *SDKSteps) agentUsesDynamicEnvParams(agent string) error {
	a.addAriesOption(agent, a.withDynamicEnvelopeParams())

	return nil
}

type edgeAgentParams struct {
	outboundTransport string // default: websocket
	returnRoute       string // default: all
}

type cloudAgentParams struct {
	host string
	port string
}

type agentInitParams struct {
	opts        []aries.Option
	autoTrigger bool
	edgeAgent   edgeAgentParams
	cloudAgent  cloudAgentParams
}

func (a *agentInitParams) append(opts ...aries.Option) {
	a.opts = append(a.opts, opts...)
}

func (a *SDKSteps) addAriesOption(agent string, opts ...createAgentOption) {
	a.agentOpts[agent] = append(a.agentOpts[agent], opts...)
}

func (a *SDKSteps) scenario(keyType, keyAgreementType, mediaTypeProfile string) error {
	a.newKeyType = kms.KeyType(keyType)
	a.newKeyAgreementType = kms.KeyType(keyAgreementType)
	a.newMediaTypeProfiles = []string{mediaTypeProfile}

	return nil
}

func (a *SDKSteps) useMediaTypeProfiles(mediaTypeProfiles string) error {
	a.newMediaTypeProfiles = strings.Split(mediaTypeProfiles, ",")

	return nil
}

// CreateAgent with the given parameters.
func (a *SDKSteps) CreateAgent(agentID, inboundHost, inboundPort, scheme string) error {
	return a.createAgentWithOptions(agentID, scheme, withHostPort(inboundHost, inboundPort))
}

func (a *SDKSteps) createAgentByDIDCommV2(agentID, inboundHost, inboundPort, scheme string) error {
	return a.createAgentWithOptions(agentID, scheme, withHostPort(inboundHost, inboundPort), withDIDCommV2())
}

func (a *SDKSteps) createConnectionV2(agent1, agent2 string) error {
	err := a.createAgentByDIDCommV2(agent1, "localhost", "random", "http")
	if err != nil {
		return fmt.Errorf("create agent %q: %w", agent1, err)
	}

	err = a.createAgentByDIDCommV2(agent2, "localhost", "random", "http")
	if err != nil {
		return fmt.Errorf("create agent %q: %w", agent2, err)
	}

	err = a.didExchangeSDKS.CreateDIDExchangeClient(strings.Join([]string{agent1, agent2}, ","))
	if err != nil {
		return err
	}

	err = a.didExchangeSDKS.RegisterPostMsgEvent(strings.Join([]string{agent1, agent2}, ","), "completed")
	if err != nil {
		return fmt.Errorf("failed to register agents for didexchange post msg events : %w", err)
	}

	err = a.didExchangeSDKS.CreateInvitation(agent1, "", "")
	if err != nil {
		return fmt.Errorf("create invitation: %w", err)
	}

	if err := a.didExchangeSDKS.ReceiveInvitation(agent2, agent1); err != nil {
		return fmt.Errorf("eeceive invitation: %w", err)
	}

	if err := a.didExchangeSDKS.ApproveRequest(agent2); err != nil {
		return fmt.Errorf("approve request %q: %w", agent2, err)
	}

	if err := a.didExchangeSDKS.ApproveRequest(agent1); err != nil {
		return fmt.Errorf("approve request %q: %w", agent1, err)
	}

	return a.didExchangeSDKS.WaitForPostEvent(strings.Join([]string{agent1, agent2}, ","), "completed")
}

func loadCertPool() (*x509.CertPool, error) {
	cp := x509.NewCertPool()
	certPrefix := "fixtures/keys/tls/"

	pemPath := fmt.Sprintf("%sec-pubCert.pem", certPrefix)

	pemData, err := ioutil.ReadFile(pemPath) //nolint:gosec
	if err != nil {
		return nil, err
	}

	ok := cp.AppendCertsFromPEM(pemData)
	if !ok {
		return nil, errors.New("failed to append certs from PEM")
	}

	return cp, nil
}

// CreateAgentWithHTTPDIDResolver creates one or more agents with HTTP DID resolver.
func (a *SDKSteps) CreateAgentWithHTTPDIDResolver(
	agents, inboundHost, inboundPort, endpointURL, acceptDidMethod string) error {
	return a.createAgents(agents, inboundHost, inboundPort, "http",
		a.withHTTPResolver(endpointURL, acceptDidMethod),
		a.withDynamicEnvelopeParams(),
		withServiceMsgTypeTargets(),
	)
}

type createAgentOption func(agentID string, params *agentInitParams) error

func (a *SDKSteps) createAgents(agents, inboundHost, inboundPort, scheme string, opts ...createAgentOption) error {
	opts = append(opts, withHostPort(inboundHost, inboundPort))

	for _, agentID := range strings.Split(agents, ",") {
		err := a.createAgentWithOptions(agentID, scheme, opts...)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *SDKSteps) createAgentWithOptions(agentID, scheme string, opts ...createAgentOption) error {
	params := &agentInitParams{}

	for _, opt := range opts {
		err := opt(agentID, params)
		if err != nil {
			return fmt.Errorf("agent sdk option: %w", err)
		}
	}

	inboundHost := params.cloudAgent.host
	if inboundHost == "" {
		inboundHost = "localhost"
	}

	inboundPort := params.cloudAgent.port
	if inboundPort == "" {
		inboundPort = "random"
	}

	storeProv := a.getStoreProvider(agentID)

	loader, err := createJSONLDDocumentLoader(storeProv)
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	params.append(
		aries.WithStoreProvider(storeProv),
		aries.WithJSONLDDocumentLoader(loader),
	)

	schemeAddrMap, err := a.cloudAgentTransports(params, inboundHost, inboundPort, scheme)
	if err != nil {
		return fmt.Errorf("initializing transports: %w", err)
	}

	err = a.createFramework(agentID, params)
	if err != nil {
		return fmt.Errorf("failed to create new agent: %w", err)
	}

	return a.checkAgentListening(agentID, schemeAddrMap)
}

func withAutoTrigger() createAgentOption {
	return func(_ string, params *agentInitParams) error {
		params.autoTrigger = true

		return nil
	}
}

func withHostPort(host, port string) createAgentOption {
	return func(_ string, params *agentInitParams) error {
		params.cloudAgent = cloudAgentParams{
			host: host,
			port: port,
		}

		return nil
	}
}

func withEdgeTransport(transportType, returnRoute string) createAgentOption {
	return func(_ string, params *agentInitParams) error {
		params.edgeAgent = edgeAgentParams{
			outboundTransport: transportType,
			returnRoute:       returnRoute,
		}

		return nil
	}
}

func (a *SDKSteps) withHTTPResolver(endpointURL, acceptDidMethod string) createAgentOption {
	return func(_ string, params *agentInitParams) error {
		url := a.bddContext.Args[endpointURL]

		if endpointURL == sideTreeURL {
			url += "identifiers"
		}

		httpVDR, err := httpbinding.New(url,
			httpbinding.WithAccept(func(method string) bool { return method == acceptDidMethod }))
		if err != nil {
			return fmt.Errorf("failed from httpbinding new ")
		}

		params.append(aries.WithVDR(httpVDR))

		return nil
	}
}

func withRemoteKMSCrypto(kmsURL, controller string) createAgentOption {
	return func(agentID string, params *agentInitParams) error {
		cp, err := loadCertPool()
		if err != nil {
			return err
		}

		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: cp}, //nolint:gosec
			},
		}

		keyStoreURL, _, err := webkms.CreateKeyStore(httpClient, kmsURL, controller, "", nil)
		if err != nil {
			return fmt.Errorf("error calling CreateKeystore: %w", err)
		}

		rKMS := webkms.New(keyStoreURL, httpClient)
		rCrypto := remotecrypto.New(keyStoreURL, httpClient)

		opts := []aries.Option{
			aries.WithKMS(func(provider kms.Provider) (kms.KeyManager, error) {
				return rKMS, nil
			}),
			aries.WithCrypto(rCrypto),
		}

		params.append(opts...)

		return nil
	}
}

func (a *SDKSteps) withRegistrar() createAgentOption {
	return func(agentID string, params *agentInitParams) error {
		msgRegistrar := msghandler.NewRegistrar()
		a.bddContext.MessageRegistrar[agentID] = msgRegistrar

		params.append(aries.WithMessageServiceProvider(msgRegistrar))

		return nil
	}
}

func withServiceMsgTypeTargets() createAgentOption {
	msgTypeTargets := []dispatcher.MessageTypeTarget{
		{
			MsgType: "present-proof/3.0/propose-presentation",
			Target:  "https://didcomm.org/present-proof/3.0/propose-presentation",
		},
		{
			MsgType: "present-proof/3.0/request-presentation",
			Target:  "https://didcomm.org/present-proof/3.0/request-presentation",
		},
	}

	return func(agentID string, params *agentInitParams) error {
		params.append(aries.WithServiceMsgTypeTargets(msgTypeTargets...))

		return nil
	}
}

func withDIDCommV2() createAgentOption {
	return func(agentID string, params *agentInitParams) error {
		params.append(aries.WithMediaTypeProfiles([]string{transport.MediaTypeDIDCommV2Profile}))

		return nil
	}
}

func (a *SDKSteps) withDynamicEnvelopeParams() createAgentOption {
	return func(agentID string, params *agentInitParams) error {
		var opts []aries.Option

		//nolint:nestif
		if g, ok := a.bddContext.Agents[agentID]; ok {
			ctx, err := g.Context()
			if err != nil {
				return fmt.Errorf("get agentID context: %w", err)
			}

			opts = append(opts, aries.WithKeyType(ctx.KeyType()), aries.WithKeyAgreementType(ctx.KeyAgreementType()),
				aries.WithMediaTypeProfiles(ctx.MediaTypeProfiles()))
		} else {
			if string(a.newKeyType) != "" {
				opts = append(opts, aries.WithKeyType(a.newKeyType))
			}

			if string(a.newKeyAgreementType) != "" {
				opts = append(opts, aries.WithKeyAgreementType(a.newKeyAgreementType))
			}

			if len(a.newMediaTypeProfiles) > 0 {
				opts = append(opts, aries.WithMediaTypeProfiles(a.newMediaTypeProfiles))
			}
		}

		params.append(opts...)

		return nil
	}
}

func (a *SDKSteps) getStoreProvider(agentID string) storage.Provider {
	storeProv := leveldb.NewProvider(dbPath + "/" + agentID + uuid.New().String())
	return storeProv
}

func (a *SDKSteps) createEdgeAgentDIDCommV1(agentID, scheme, routeOpt string) error {
	return a.createEdgeAgent(agentID, withEdgeTransport(scheme, routeOpt))
}

func (a *SDKSteps) createEdgeAgent(agentID string, opts ...createAgentOption) error {
	params := &agentInitParams{}

	for _, opt := range opts {
		err := opt(agentID, params)
		if err != nil {
			return err
		}
	}

	scheme := params.edgeAgent.outboundTransport
	if scheme == "" {
		scheme = "websocket"
	}

	routeOpt := params.edgeAgent.returnRoute
	if routeOpt == "" {
		routeOpt = "all"
	}

	storeProv := a.getStoreProvider(agentID)

	loader, err := createJSONLDDocumentLoader(storeProv)
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	params.append(
		aries.WithStoreProvider(storeProv),
		aries.WithJSONLDDocumentLoader(loader),
	)

	err = a.withHTTPResolver(sideTreeURL, "sidetree")(agentID, params)
	if err != nil {
		return fmt.Errorf("create http resolver: %w", err)
	}

	err = a.edgeAgentTransports(params, scheme, routeOpt)
	if err != nil {
		return err
	}

	return a.createFramework(agentID, params)
}

func (a *SDKSteps) edgeAgentTransports(params *agentInitParams, scheme, routeOpt string) error {
	if routeOpt != decorator.TransportReturnRouteAll {
		return errors.New("only 'all' transport route return option is supported")
	}

	params.append(aries.WithTransportReturnRoute(routeOpt))

	sch := strings.Split(scheme, ",")

	for _, s := range sch {
		switch s {
		case webSocketTransportProvider:
			params.append(aries.WithOutboundTransports(ws.NewOutbound()))
		case httpTransportProvider:
			out, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
			if err != nil {
				return fmt.Errorf("failed to create http outbound: %w", err)
			}

			params.append(aries.WithOutboundTransports(ws.NewOutbound(), out))
		default:
			return fmt.Errorf("invalid transport provider type : %s (only websocket/http is supported)", scheme)
		}
	}

	return nil
}

func (a *SDKSteps) cloudAgentTransports(params *agentInitParams, inboundHosts, inboundPorts, schemes string) (map[string]string, error) {
	const portAttempts = 5

	scheme := strings.Split(schemes, ",")
	hosts := strings.Split(inboundHosts, ",")
	ports := strings.Split(inboundPorts, ",")
	schemeAddrMap := make(map[string]string)

	for i := 0; i < len(scheme); i++ {
		port := ports[i]
		if port == "random" {
			port = strconv.Itoa(mustGetRandomPort(portAttempts))
		}

		inboundAddr := fmt.Sprintf("%s:%s", hosts[i], port)

		schemeAddrMap[scheme[i]] = inboundAddr
	}

	for _, s := range scheme {
		switch s {
		case webSocketTransportProvider:
			inbound, err := ws.NewInbound(schemeAddrMap[s], "ws://"+schemeAddrMap[s], "", "")
			if err != nil {
				return nil, fmt.Errorf("failed to create websocket: %w", err)
			}

			params.append(aries.WithInboundTransport(inbound), aries.WithOutboundTransports(ws.NewOutbound()))
		case httpTransportProvider:
			params.append(defaults.WithInboundHTTPAddr(schemeAddrMap[s], "http://"+schemeAddrMap[s], "", ""))

			out, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
			if err != nil {
				return nil, fmt.Errorf("failed to create http outbound: %w", err)
			}

			params.append(aries.WithOutboundTransports(ws.NewOutbound(), out))
		default:
			return nil, fmt.Errorf("invalid transport provider type : %s (only websocket/http is supported)", scheme)
		}
	}

	return schemeAddrMap, nil
}

func (a *SDKSteps) checkAgentListening(agentID string, schemeAddrMap map[string]string) error {
	const listenTimeout = 2 * time.Second

	for _, inboundAddr := range schemeAddrMap {
		if err := listenFor(inboundAddr, listenTimeout); err != nil {
			return err
		}

		logger.Debugf("Agent %s start listening on %s", agentID, inboundAddr)
	}

	return nil
}

func (a *SDKSteps) createFramework(agentID string, params *agentInitParams) error {
	agent, err := aries.New(params.opts...)
	if err != nil {
		return fmt.Errorf("failed to create new agent: %w", err)
	}

	ctx, err := agent.Context()
	if err != nil {
		return fmt.Errorf("failed to create context: %w", err)
	}

	a.bddContext.Agents[agentID] = agent
	a.bddContext.AgentCtx[agentID] = ctx
	a.bddContext.Messengers[agentID] = agent.Messenger()

	if params.autoTrigger {
		err = autoServiceTriggering(ctx)
		if err != nil {
			return fmt.Errorf("failed to auto trigger services: %w", err)
		}
	}

	return nil
}

type svcProvider interface {
	Service(id string) (interface{}, error)
}

func autoServiceTriggering(ctx svcProvider) error {
	srvc, err := ctx.Service(presentproof.Name)
	if err != nil {
		return err
	}

	ppSvc, ok := srvc.(*presentproof.Service)
	if !ok {
		return fmt.Errorf("present proof service is not of type %T", &presentproof.Service{})
	}

	// auto service for presentproof
	events := make(chan service.DIDCommAction)

	err = ppSvc.RegisterActionEvent(events)
	if err != nil {
		return err
	}

	go service.AutoExecuteActionEvent(events)

	return nil
}

type provider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *provider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *provider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func createJSONLDDocumentLoader(storageProvider storage.Provider) (jsonld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(cachedstore.NewProvider(storageProvider, mem.NewProvider()))
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	p := &provider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	loader, err := ld.NewDocumentLoader(p, ld.WithExtraContexts(bddldcontext.Extra()...))
	if err != nil {
		return nil, err
	}

	return loader, nil
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *SDKSteps) SetContext(ctx *context.BDDContext) {
	// clear agentOpts when resetting steps context.
	a.agentOpts = map[string][]createAgentOption{}

	a.bddContext = ctx

	a.didExchangeSDKS = didexchangebdd.NewDIDExchangeSDKSteps()
	a.didExchangeSDKS.SetContext(ctx)
}

func mustGetRandomPort(n int) int {
	for ; n > 0; n-- {
		port, err := getRandomPort()
		if err != nil {
			continue
		}

		return port
	}

	panic("cannot acquire the random port")
}

func getRandomPort() (int, error) {
	const network = "tcp"

	addr, err := net.ResolveTCPAddr(network, "localhost:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP(network, addr)
	if err != nil {
		return 0, err
	}

	if err := listener.Close(); err != nil {
		return 0, err
	}

	return listener.Addr().(*net.TCPAddr).Port, nil
}

func listenFor(host string, d time.Duration) error {
	timeout := time.After(d)

	for {
		select {
		case <-timeout:
			return errors.New("timeout: server is not available")
		default:
			conn, err := net.Dial("tcp", host)
			if err != nil {
				continue
			}

			return conn.Close()
		}
	}
}
