/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package aries-agentd (Aries Agent Server) of aries-framework-go.
//
//
// Terms Of Service:
//
//
//     Schemes: http, https
//     Host: 127.0.0.1:8080
//     Version: 0.1.0
//     License: Copyright SecureKey Technologies Inc. All Rights Reserved.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
package main

import (
	"net/http"
	"os"

	"github.com/go-openapi/runtime/middleware/denco"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didcommtrans "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/restapi"
)

const agentHostEnvKey = "ARIESD_API_HOST"
const agentHTTPInboundEnvKey = "ARIESD_INBOUND_HOST"

var logger = log.New("aries-framework/agentd")

// This is an application which starts Aries agent controller API on given port
func main() {

	//Default port and command lines arguments will be addressed as part of #94
	host := os.Getenv(agentHostEnvKey)
	if host == "" {
		logger.Errorf("Unable to start aries agentd, host not provided")
		return
	}

	//Default port and command lines arguments will be addressed as part of #94
	inboundHost := os.Getenv(agentHTTPInboundEnvKey)
	if inboundHost == "" {
		logger.Errorf("Unable to start aries agentd, HTTP Inbound transport host not provided")
		return
	}

	framework, err := aries.New()
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], failed to initialize framework :  %s", host, err)
	}

	ctx, err := framework.Context()
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], failed to get aries context :  %s", host, err)
	}

	// start the HTTP inbound transport
	startInboundHTTPTransport(ctx, inboundHost)

	mux := denco.NewMux()

	//get all HTTP REST API handlers available for controller API
	restService, err := restapi.New(ctx)
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], failed to get rest service api :  %s", host, err)
	}
	handlers := restService.GetOperations()

	//register handlers
	var routes []denco.Handler
	for _, handler := range handlers {
		routes = append(routes, mux.Handler(handler.Method(), handler.Path(), handler.Handle()))
	}

	//build router
	handler, err := mux.Build(routes)
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], cause:  %s", host, err)
	}

	logger.Infof("Starting aries agentd on host [%s]", host)

	//start server on given port and serve using given handlers
	err = http.ListenAndServe(host, handler)
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], cause:  %s", host, err)
	}
}

// startInboundHTTPTransport starts a HTTP server for agent inbound communication. The message handlers provided by the
// context are passed to framework provided http.NewInboundHandler function. This function returns the http.Handler,
// which will be used to start the HTTP server.
// TODO the framework provides the inbound message handlers and doesnt provide means of transport ie, http server
// https://github.com/hyperledger/aries-framework-go/issues/176
func startInboundHTTPTransport(ctx *context.Provider, inboundHost string) {
	// get the http.Handler from framework by passing the inbound message handler
	msgHandler, err := didcommtrans.NewInboundHandler(ctx)
	if err != nil {
		logger.Fatalf("failed to get http handler from framework inbound message handler: %w", inboundHost, err)
	}

	// start the http server
	go func() {
		err := http.ListenAndServe(inboundHost, msgHandler)
		if err != nil {
			logger.Fatalf("Failed to start aries HTTP inbound transport on port [%s], cause:  %s", inboundHost, err)
		}
	}()

}
