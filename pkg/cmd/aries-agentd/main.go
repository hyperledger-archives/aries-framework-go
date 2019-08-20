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
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

const agentHostEnvKey = "ARIESD_API_HOST"

var logger = log.New("aries-framework/agentd")

// This is an application which starts Aries agent controller API on given port
func main() {

	//Default port and command lines arguments will be addressed as part of #94
	host := os.Getenv(agentHostEnvKey)
	if host == "" {
		logger.Errorf("Unable to start aries agentd, host not provided")
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

	mux := denco.NewMux()

	//get all HTTP REST API handlers available for controller API
	handlers := ctx.RESTHandlers()

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
