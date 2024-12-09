/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Boran Car <boran.car@gmail.com>. All Rights Reserved.
Copyright Christian Nuss <christian@scaffold.ly>, Founder, Scaffoldly LLC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/subtle"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/controller"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	wsinternal "github.com/hyperledger/aries-framework-go/cmd/aries-agent-lambda/transport/apigw_ws"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	httpinternal "github.com/hyperledger/aries-framework-go/cmd/aries-agent-lambda/transport/apigw_http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	ariescontext "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-lambda/storage/dynamodb"
)

type dbParam struct {
	dbType string
	// prefix  string
	// timeout uint64
}

type agentParameters struct {
	// server                                         server
	host, defaultLabel, transportReturnRoute       string
	tlsCertFile, tlsKeyFile                        string
	token, keyType, keyAgreementType               string
	webhookURLs, httpResolvers, outboundTransports []string
	inboundHostInternals, inboundHostExternals     []string
	contextProviderURLs, mediaTypeProfiles         []string
	autoAccept                                     bool
	msgHandler                                     command.MessageHandler
	dbParam                                        *dbParam
	autoExecuteRFC0593                             bool
}

const (
	httpProtocol      = "http"
	websocketProtocol = "ws"
	defaultWebhookUrl = "https://sly.slygo.scaffoldly.dev/aries-webhooks/api/v1/webhooks"
)

var (
	keyTypes = map[string]kms.KeyType{
		"ed25519":           kms.ED25519Type,
		"ecdsap256ieee1363": kms.ECDSAP256TypeIEEEP1363,
		"ecdsap256der":      kms.ECDSAP256TypeDER,
		"ecdsap384ieee1363": kms.ECDSAP384TypeIEEEP1363,
		"ecdsap384der":      kms.ECDSAP384TypeDER,
		"ecdsap521ieee1363": kms.ECDSAP521TypeIEEEP1363,
		"ecdsap521der":      kms.ECDSAP521TypeDER,
	}

	keyAgreementTypes = map[string]kms.KeyType{
		"x25519kw": kms.X25519ECDHKWType,
		"p256kw":   kms.NISTP256ECDHKWType,
		"p384kw":   kms.NISTP384ECDHKWType,
		"p521kw":   kms.NISTP521ECDHKWType,
	}
)

func RegisterRoutes(router *mux.Router) (*mux.Router, error) {
	// Tidbits from https://github.com/hyperledger/aries-framework-go/blob/9446ee81c3b4f39ca9f7af4abcf7cb4cc594e968/cmd/aries-agent-rest/startcmd/start.go#L736
	dbParam := &dbParam{
		dbType: "dynamodb",
	}

	httpProto := "https"
	wsProto := "wss"
	stage := os.Getenv("STAGE")
	httpHost := os.Getenv("API_GATEWAY_DOMAIN")
	wsHost := os.Getenv("API_GATEWAY_WEBSOCKET_DOMAIN")
	internalHttpHost := httpHost
	// internalWsHost := wsHost
	basePath := os.Getenv("SERVICE_SLUG")
	webhookPath := fmt.Sprintf("/%s/%s", basePath, "webhook")
	if stage == "local" {
		httpProto = "http"
		wsProto = "ws"
		httpHost = "localhost:3000"
		wsHost = "localhost:3001"
		internalHttpHost = "host.docker.internal:3000"
		// internalWsHost = "host.docker.internal:3001"
	}
	inboundHttpHost := fmt.Sprintf("http@%s", httpHost)
	log.Printf("Inbound Http Host: %s", inboundHttpHost)
	inboundWsHost := fmt.Sprintf("ws@%s", wsHost)
	log.Printf("Inbound Ws Host: %s", inboundWsHost)
	inboundHostHttpExternalUrl := fmt.Sprintf("http@%s://%s/%s", httpProto, httpHost, basePath)
	log.Printf("Inbound Http Host External URL: %s", inboundHostHttpExternalUrl)
	inboundHostWsExternalUrl := fmt.Sprintf("ws@%s://%s/%s", wsProto, wsHost, basePath)
	log.Printf("Inbound Ws Host External URL: %s", inboundHostWsExternalUrl)
	// TODO: Convert defaultWebhookUrl to Environment Variables
	webhookUrls := []string{defaultWebhookUrl, fmt.Sprintf("%s://%s%s", httpProto, internalHttpHost, webhookPath)}
	log.Printf("Webhook URLs: %s", webhookUrls)

	parameters := &agentParameters{
		// server:               server,
		host: httpHost,
		// token:                token,
		inboundHostInternals: []string{inboundWsHost},
		inboundHostExternals: []string{inboundHostWsExternalUrl},
		dbParam:              dbParam,
		// defaultLabel:         defaultLabel,
		webhookURLs: webhookUrls,
		// httpResolvers:        httpResolvers,
		outboundTransports: []string{"ws"},
		autoAccept: true,
		transportReturnRoute: "all",
		// contextProviderURLs:  contextProviderURLs,
		// tlsCertFile:          tlsCertFile,
		// tlsKeyFile:           tlsKeyFile,
		// autoExecuteRFC0593:   autoExecuteRFC0593,
		// keyType:              keyType,
		// keyAgreementType:     keyAgreementType,
		// mediaTypeProfiles:    mediaTypeProfiles,
	}

	parameters.msgHandler = msghandler.NewRegistrar()

	actx, err := createAriesAgent(parameters)
	if err != nil {
		return nil, err
	}

	handlers, err := controller.GetRESTHandlers(actx, controller.WithWebhookURLs(parameters.webhookURLs...),
		controller.WithDefaultLabel(parameters.defaultLabel), controller.WithAutoAccept(parameters.autoAccept),
		controller.WithMessageHandler(parameters.msgHandler),
		controller.WithAutoExecuteRFC0593(parameters.autoExecuteRFC0593))
	if err != nil {
		return nil, err
	}

	if parameters.token != "" {
		router.Use(authorizationMiddleware(parameters.token))
	}

	for _, handler := range handlers {
		path := fmt.Sprintf("/%s%s", basePath, handler.Path())
		//log.Printf("Registering Path: %s %s", handler.Method(), handler.Path())
		router.HandleFunc(path, handler.Handle()).Methods(handler.Method())
	}

	router.HandleFunc(webhookPath, webhookHandler).Methods(http.MethodPost)
	router.HandleFunc("/ws", wsinternal.NewInboundHandler()).Methods(http.MethodPut, http.MethodPost, http.MethodDelete)
	router.HandleFunc(fmt.Sprintf("/%s", basePath), httpinternal.NewInboundHandler()).Methods(http.MethodPost)

	return router, nil
}

func createAriesAgent(parameters *agentParameters) (*ariescontext.Provider, error) {
	var opts []aries.Option

	storePro := dynamodb.NewProvider() // TODO Other Storage Providers

	opts = append(opts, aries.WithStoreProvider(storePro))
	opts = append(opts, aries.WithProtocolStateStoreProvider(storePro))

	if parameters.transportReturnRoute != "" {
		opts = append(opts, aries.WithTransportReturnRoute(parameters.transportReturnRoute))
	}

	inboundTransportOpt, err := getInboundTransportOpts(parameters.inboundHostInternals,
		parameters.inboundHostExternals, parameters.tlsCertFile, parameters.tlsKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to inbound tranpsort opt : %w",
			parameters.host, err)
	}

	opts = append(opts, inboundTransportOpt...)

	resolverOpts, err := getResolverOpts(parameters.httpResolvers)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to resolver opts : %w",
			parameters.host, err)
	}

	opts = append(opts, resolverOpts...)

	outboundTransportOpts, err := getOutboundTransportOpts(parameters.outboundTransports)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to outbound transport opts : %w",
			parameters.host, err)
	}

	opts = append(opts, outboundTransportOpts...)
	opts = append(opts, aries.WithMessageServiceProvider(parameters.msgHandler))

	if len(parameters.contextProviderURLs) > 0 {
		opts = append(opts, aries.WithJSONLDContextProviderURL(parameters.contextProviderURLs...))
	}

	if kt, ok := keyTypes[parameters.keyType]; ok {
		opts = append(opts, aries.WithKeyType(kt))
	}

	if kat, ok := keyAgreementTypes[parameters.keyAgreementType]; ok {
		opts = append(opts, aries.WithKeyAgreementType(kat))
	}

	if len(parameters.mediaTypeProfiles) > 0 {
		opts = append(opts, aries.WithMediaTypeProfiles(parameters.mediaTypeProfiles))
	}

	framework, err := aries.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to initialize framework :  %w",
			parameters.host, err)
	}

	ctx, err := framework.Context()
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to get aries context : %w",
			parameters.host, err)
	}

	return ctx, nil
}

// TODO Haven't dug into this to see if it needs to be tweaked for Serverlesss + Lambda
func getOutboundTransportOpts(outboundTransports []string) ([]aries.Option, error) {
	var opts []aries.Option

	var transports []transport.OutboundTransport

	for _, outboundTransport := range outboundTransports {
		switch outboundTransport {
		case httpProtocol:
			outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
			if err != nil {
				return nil, fmt.Errorf("http outbound transport initialization failed: %w", err)
			}

			transports = append(transports, outbound)
		case websocketProtocol:
			transports = append(transports, wsinternal.NewOutbound())
		default:
			return nil, fmt.Errorf("outbound transport [%s] not supported", outboundTransport)
		}
	}

	if len(transports) > 0 {
		opts = append(opts, aries.WithOutboundTransports(transports...))
	}

	return opts, nil
}

func getInboundTransportOpts(inboundHostInternals, inboundHostExternals []string, certFile,
	keyFile string) ([]aries.Option, error) {
	internalHost, err := getInboundSchemeToURLMap(inboundHostInternals)
	if err != nil {
		return nil, fmt.Errorf("inbound internal host : %w", err)
	}

	externalHost, err := getInboundSchemeToURLMap(inboundHostExternals)
	if err != nil {
		return nil, fmt.Errorf("inbound external host : %w", err)
	}

	var opts []aries.Option

	for scheme := range internalHost {
		switch scheme {
		case httpProtocol:
			inboundHttp := httpinternal.WithInboundHTTP(externalHost[scheme])
			opts = append(opts, inboundHttp)
		case websocketProtocol:
			inboundWs := wsinternal.WithInboundWS(externalHost[scheme])
			opts = append(opts, inboundWs)
		default:
			return nil, fmt.Errorf("inbound transport [%s] not supported", scheme)
		}
	}

	return opts, nil
}

// TODO Haven't dug into this to see if it needs to be tweaked for Serverlesss + Lambda
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

// TODO Haven't dug into this to see if it needs to be tweaked for Serverlesss + Lambda
func validateAuthorizationBearerToken(w http.ResponseWriter, r *http.Request, token string) bool {
	actHdr := r.Header.Get("Authorization")
	expHdr := "Bearer " + token

	if subtle.ConstantTimeCompare([]byte(actHdr), []byte(expHdr)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorised.\n")) // nolint:gosec,errcheck

		return false
	}

	return true
}

// TODO Haven't dug into this to see if it needs to be tweaked for Serverlesss + Lambda
func authorizationMiddleware(token string) mux.MiddlewareFunc {
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if validateAuthorizationBearerToken(w, r, token) {
				next.ServeHTTP(w, r)
			}
		})
	}

	return middleware
}

// TODO Haven't dug into this to see if it needs to be tweaked for Serverlesss + Lambda
func getInboundSchemeToURLMap(schemeHostStr []string) (map[string]string, error) {
	const validSliceLen = 2

	schemeHostMap := make(map[string]string)

	for _, schemeHost := range schemeHostStr {
		schemeHostSlice := strings.Split(schemeHost, "@")
		if len(schemeHostSlice) != validSliceLen {
			return nil, fmt.Errorf("invalid inbound host option: Use scheme@url to pass the option")
		}

		schemeHostMap[schemeHostSlice[0]] = schemeHostSlice[1]
	}

	return schemeHostMap, nil
}

const (
	topicsSize   = 5000
	topicTimeout = 100 * time.Millisecond
)

var topics = make(chan []byte, topicsSize)

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	w.WriteHeader(http.StatusNoContent)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	log.Printf("received topic message: %s", string(msg))

	topics <- msg
}
