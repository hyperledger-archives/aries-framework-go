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
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
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
}

// NewSDKSteps returns new agent from client SDK.
func NewSDKSteps() *SDKSteps {
	return &SDKSteps{}
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
	return a.createAgentWithOptions(agentID, inboundHost, inboundPort, scheme, false)
}

// createAgentByDIDCommV2 with the given parameters.
func (a *SDKSteps) createAgentByDIDCommV2(agentID, inboundHost, inboundPort, scheme string) error {
	return a.createAgentWithOptions(agentID, inboundHost, inboundPort, scheme, false, withDIDCommV2())
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

// CreateAgentWithRemoteKMS with the given parameters with a remote kms.
func (a *SDKSteps) CreateAgentWithRemoteKMS(agentID, inboundHost, inboundPort, scheme,
	kmsURL, controller string) error {
	return a.createAgentWithOptions(agentID, inboundHost, inboundPort, scheme, false,
		withRemoteKMSCrypto(kmsURL, controller))
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

func (a *SDKSteps) createAgentWithRegistrar(agentID, inboundHost, inboundPort, scheme string) error {
	return a.createAgentWithOptions(agentID, inboundHost, inboundPort, scheme, false, withRegistrar())
}

func (a *SDKSteps) createAgentWithRegistrarAndHTTPDIDResolver(agentID, inboundHost, inboundPort,
	scheme, endpointURL, acceptDidMethod string) error {
	return a.createAgentWithOptions(agentID, inboundHost, inboundPort, scheme, false,
		withRegistrar(), withHTTPResolver(endpointURL, acceptDidMethod))
}

// CreateAgentWithHTTPDIDResolver creates one or more agents with HTTP DID resolver.
func (a *SDKSteps) CreateAgentWithHTTPDIDResolver(
	agents, inboundHost, inboundPort, endpointURL, acceptDidMethod string) error {
	return a.createAgentWithHTTPDIDResolverAndServiceTriggering(agents, inboundHost, inboundPort, endpointURL,
		acceptDidMethod, false)
}

// CreateAgentWithHTTPDIDResolverAndOOBv2 creates one or more agents with HTTP DID resolver and services with auto event
// registration.
func (a *SDKSteps) CreateAgentWithHTTPDIDResolverAndOOBv2(
	agents, inboundHost, inboundPort, endpointURL, acceptDidMethod string) error {
	return a.createAgentWithHTTPDIDResolverAndServiceTriggering(agents, inboundHost, inboundPort, endpointURL,
		acceptDidMethod, true)
}

func (a *SDKSteps) createAgentWithHTTPDIDResolverAndServiceTriggering(
	agents, inboundHost, inboundPort, endpointURL, acceptDidMethod string, autoTrigger bool) error {
	for _, agentID := range strings.Split(agents, ",") {
		err := a.createAgentWithOptions(agentID, inboundHost, inboundPort, "http", autoTrigger,
			withHTTPResolver(endpointURL, acceptDidMethod),
			withDynamicEnvelopeParams(),
			withServiceMsgTypeTargets(),
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// CreateAgentWithFlags takes a set of comma-separated flags or key-value pairs:
//  - sidetree=[endpoint url]: use http binding VDR accepting sidetree DID method, with the given http binding url.
//  - DIDCommV2: use DIDComm V2 only.
//  - UseRegistrar: use message registrar.
func (a *SDKSteps) CreateAgentWithFlags(agentID, inboundHost, inboundPort, scheme, flags string) error {
	var opts []createAgentOption

	flagList := strings.Split(flags, ",")

	flagMap := make(map[string]string)

	for _, flag := range flagList {
		flagSplit := strings.Split(flag, "=")

		switch len(flagSplit) {
		case 1:
			flagMap[flagSplit[0]] = ""
		case 2: // nolint:gomnd // 2 parts means a flag with value
			flagMap[flagSplit[0]] = flagSplit[1]
		default:
			return fmt.Errorf("failed to parse flag: %s", flag)
		}
	}

	if endpointURL, ok := flagMap["sidetree"]; ok {
		opts = append(opts, withHTTPResolver(endpointURL, "sidetree"))
	}

	if _, ok := flagMap["UseRegistrar"]; ok {
		opts = append(opts, withRegistrar())
	}

	if _, ok := flagMap["DIDCommV2"]; ok {
		opts = append(opts, withDIDCommV2())
	}

	return a.createAgentWithOptions(agentID, inboundHost, inboundPort, scheme, false, opts...)
}

type createAgentOption func(steps *SDKSteps, agentID string) ([]aries.Option, error)

func (a *SDKSteps) createAgentWithOptions(agentID, inboundHost, inboundPort,
	scheme string, autoTrigger bool, opts ...createAgentOption) error {
	storeProv := a.getStoreProvider(agentID)

	loader, err := createJSONLDDocumentLoader(storeProv)
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	ariesOpts := []aries.Option{aries.WithStoreProvider(storeProv), aries.WithJSONLDDocumentLoader(loader)}

	for _, opt := range opts {
		newOpts, err := opt(a, agentID)
		if err != nil {
			return fmt.Errorf("agent sdk option: %w", err)
		}

		ariesOpts = append(ariesOpts, newOpts...)
	}

	return a.create(agentID, inboundHost, inboundPort, scheme, autoTrigger, ariesOpts...)
}

func withHTTPResolver(endpointURL, acceptDidMethod string) createAgentOption {
	return func(steps *SDKSteps, _ string) ([]aries.Option, error) {
		url := steps.bddContext.Args[endpointURL]

		if endpointURL == sideTreeURL {
			url += "identifiers"
		}

		httpVDR, err := httpbinding.New(url,
			httpbinding.WithAccept(func(method string) bool { return method == acceptDidMethod }))
		if err != nil {
			return nil, fmt.Errorf("failed from httpbinding new ")
		}

		return []aries.Option{aries.WithVDR(httpVDR)}, nil
	}
}

func withRemoteKMSCrypto(kmsURL, controller string) createAgentOption {
	return func(a *SDKSteps, agentID string) ([]aries.Option, error) {
		cp, err := loadCertPool()
		if err != nil {
			return nil, err
		}

		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: cp}, //nolint:gosec
			},
		}

		keyStoreURL, _, err := webkms.CreateKeyStore(httpClient, kmsURL, controller, "", nil)
		if err != nil {
			return nil, fmt.Errorf("error calling CreateKeystore: %w", err)
		}

		rKMS := webkms.New(keyStoreURL, httpClient)
		rCrypto := remotecrypto.New(keyStoreURL, httpClient)

		opts := []aries.Option{
			aries.WithKMS(func(provider kms.Provider) (kms.KeyManager, error) {
				return rKMS, nil
			}),
			aries.WithCrypto(rCrypto),
		}

		return opts, nil
	}
}

func withRegistrar() createAgentOption {
	return func(steps *SDKSteps, agentID string) ([]aries.Option, error) {
		msgRegistrar := msghandler.NewRegistrar()
		steps.bddContext.MessageRegistrar[agentID] = msgRegistrar

		return []aries.Option{aries.WithMessageServiceProvider(msgRegistrar)}, nil
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

	return func(steps *SDKSteps, agentID string) ([]aries.Option, error) {
		return []aries.Option{aries.WithServiceMsgTypeTargets(msgTypeTargets...)}, nil
	}
}

func withDIDCommV2() createAgentOption {
	return func(steps *SDKSteps, agentID string) ([]aries.Option, error) {
		return []aries.Option{aries.WithMediaTypeProfiles([]string{transport.MediaTypeDIDCommV2Profile})}, nil
	}
}

func withDynamicEnvelopeParams() createAgentOption {
	return func(steps *SDKSteps, agentID string) ([]aries.Option, error) {
		var opts []aries.Option

		//nolint:nestif
		if g, ok := steps.bddContext.Agents[agentID]; ok {
			ctx, err := g.Context()
			if err != nil {
				return nil, fmt.Errorf("get agentID context: %w", err)
			}

			opts = append(opts, aries.WithKeyType(ctx.KeyType()), aries.WithKeyAgreementType(ctx.KeyAgreementType()),
				aries.WithMediaTypeProfiles(ctx.MediaTypeProfiles()))
		} else {
			if string(steps.newKeyType) != "" {
				opts = append(opts, aries.WithKeyType(steps.newKeyType))
			}

			if string(steps.newKeyAgreementType) != "" {
				opts = append(opts, aries.WithKeyAgreementType(steps.newKeyAgreementType))
			}

			if len(steps.newMediaTypeProfiles) > 0 {
				opts = append(opts, aries.WithMediaTypeProfiles(steps.newMediaTypeProfiles))
			}
		}

		return opts, nil
	}
}

func (a *SDKSteps) getStoreProvider(agentID string) storage.Provider {
	storeProv := leveldb.NewProvider(dbPath + "/" + agentID + uuid.New().String())
	return storeProv
}

func (a *SDKSteps) createEdgeAgent(agentID, scheme, routeOpt string) error {
	return a.createEdgeAgentByDIDCommVer(agentID, scheme, routeOpt, false)
}

func (a *SDKSteps) createEdgeAgentByDIDCommV2(agentID, scheme, routeOpt string) error {
	return a.createEdgeAgentByDIDCommVer(agentID, scheme, routeOpt, true)
}

func (a *SDKSteps) createEdgeAgentByDIDCommVer(agentID, scheme, routeOpt string, useDIDCommV2 bool) error {
	var opts []aries.Option

	storeProv := a.getStoreProvider(agentID)

	if routeOpt != decorator.TransportReturnRouteAll {
		return errors.New("only 'all' transport route return option is supported")
	}

	loader, err := createJSONLDDocumentLoader(storeProv)
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	resolverOpts, err := withHTTPResolver(sideTreeURL, "sidetree")(a, agentID)
	if err != nil {
		return fmt.Errorf("create http resolver: %w", err)
	}

	opts = append(opts,
		aries.WithStoreProvider(storeProv),
		aries.WithTransportReturnRoute(routeOpt),
		aries.WithJSONLDDocumentLoader(loader),
	)

	opts = append(opts, resolverOpts...)

	if useDIDCommV2 {
		opts = append(opts, aries.WithMediaTypeProfiles([]string{transport.MediaTypeDIDCommV2Profile}))
	}

	sch := strings.Split(scheme, ",")

	for _, s := range sch {
		switch s {
		case webSocketTransportProvider:
			opts = append(opts, aries.WithOutboundTransports(ws.NewOutbound()))
		case httpTransportProvider:
			out, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
			if err != nil {
				return fmt.Errorf("failed to create http outbound: %w", err)
			}

			opts = append(opts, aries.WithOutboundTransports(ws.NewOutbound(), out))
		default:
			return fmt.Errorf("invalid transport provider type : %s (only websocket/http is supported)", scheme)
		}
	}

	return a.createFramework(agentID, false, opts...)
}

//nolint: gocyclo
func (a *SDKSteps) create(agentID, inboundHosts, inboundPorts, schemes string, autoTrigger bool,
	opts ...aries.Option) error {
	const (
		portAttempts  = 5
		listenTimeout = 2 * time.Second
	)

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
				return fmt.Errorf("failed to create websocket: %w", err)
			}

			opts = append(opts, aries.WithInboundTransport(inbound), aries.WithOutboundTransports(ws.NewOutbound()))
		case httpTransportProvider:
			opts = append(opts, defaults.WithInboundHTTPAddr(schemeAddrMap[s], "http://"+schemeAddrMap[s], "", ""))

			out, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
			if err != nil {
				return fmt.Errorf("failed to create http outbound: %w", err)
			}

			opts = append(opts, aries.WithOutboundTransports(ws.NewOutbound(), out))
		default:
			return fmt.Errorf("invalid transport provider type : %s (only websocket/http is supported)", scheme)
		}
	}

	err := a.createFramework(agentID, autoTrigger, opts...)
	if err != nil {
		return fmt.Errorf("failed to create new agent: %w", err)
	}

	for _, inboundAddr := range schemeAddrMap {
		if err := listenFor(inboundAddr, listenTimeout); err != nil {
			return err
		}

		logger.Debugf("Agent %s start listening on %s", agentID, inboundAddr)
	}

	return nil
}

func (a *SDKSteps) createFramework(agentID string, autoTrigger bool, opts ...aries.Option) error {
	agent, err := aries.New(opts...)
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

	if autoTrigger {
		err = autoServiceTriggering(ctx.AllServices())
		if err != nil {
			return fmt.Errorf("failed to auto trigger services: %w", err)
		}
	}

	return nil
}

func autoServiceTriggering(services []dispatcher.ProtocolService) error {
	// auto service for OOBV2 target services
	for _, srvc := range services {
		// for now, only PresentProof service is a possible OOBv2 target service, add other services as needed.
		if srvc.Name() != presentproof.Name {
			continue
		}

		ppSvc, ok := srvc.(*presentproof.Service)
		if !ok {
			return fmt.Errorf("present proof service is not of type %T", &presentproof.Service{})
		}

		// auto service for presentproof
		events := make(chan service.DIDCommAction)

		err := ppSvc.RegisterActionEvent(events)
		if err != nil {
			return err
		}

		go service.AutoExecuteActionEvent(events)
	}

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
	a.bddContext = ctx

	a.didExchangeSDKS = didexchangebdd.NewDIDExchangeSDKSteps()
	a.didExchangeSDKS.SetContext(ctx)
}

// RegisterSteps registers agent steps.
func (a *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with "([^"]*)" as the transport provider$`,
		a.CreateAgent)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with "([^"]*)" using DIDCommV2 as `+
		`the transport provider$`,
		a.createAgentByDIDCommV2)
	s.Step(`^"([^"]*)" exchange DIDs V2 with "([^"]*)"$`, a.createConnectionV2)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with "([^"]*)" as the transport provider `+
		`using webkms with key server at "([^"]*)" URL, using "([^"]*)" controller`, a.CreateAgentWithRemoteKMS)
	s.Step(`^"([^"]*)" edge agent is running with "([^"]*)" as the outbound transport provider `+
		`and "([^"]*)" as the transport return route option`, a.createEdgeAgent)
	s.Step(`^"([^"]*)" edge agent is running with "([^"]*)" as the outbound transport provider `+
		`and "([^"]*)" using DIDCommV2 as the transport return route option`, a.createEdgeAgentByDIDCommV2)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" `+
		`with http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`, a.CreateAgentWithHTTPDIDResolver)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" `+
		`with http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)" and auto triggered services$`,
		a.CreateAgentWithHTTPDIDResolverAndOOBv2)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with "([^"]*)" as the transport provider `+
		`and "([^"]*)" flags$`, a.CreateAgentWithFlags)
	s.Step(`^"([^"]*)" agent with message registrar is running on "([^"]*)" port "([^"]*)" `+
		`with "([^"]*)" as the transport provider$`, a.createAgentWithRegistrar)
	s.Step(`^"([^"]*)" agent with message registrar is running on "([^"]*)" port "([^"]*)" with "([^"]*)" `+
		`as the transport provider and http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`,
		a.createAgentWithRegistrarAndHTTPDIDResolver)
	s.Step(`^options ""([^"]*)"" ""([^"]*)"" ""([^"]*)""$`, a.scenario)
	s.Step(`^all agents are using Media Type Profiles "([^"]*)"$`, a.useMediaTypeProfiles)
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
