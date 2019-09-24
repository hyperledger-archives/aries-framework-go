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
//     License: SPDX-License-Identifier: Apache-2.0
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

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/restapi"
)

const agentHostEnvKey = "ARIESD_API_HOST"
const agentHTTPInboundEnvKey = "ARIESD_INBOUND_HOST"
const agentDBPathEnvKey = "ARIESD_DB_PATH"

var logger = log.New("aries-framework/agentd")

// This is an application which starts Aries agent controller API on given port
func main() {
	// Default port and command lines arguments will be addressed as part of #94
	host := os.Getenv(agentHostEnvKey)
	if host == "" {
		logger.Errorf("Unable to start aries agentd, host not provided")
		return
	}

	// Default port and command lines arguments will be addressed as part of #94
	var opts []aries.Option
	inboundHost := os.Getenv(agentHTTPInboundEnvKey)
	if inboundHost == "" {
		logger.Errorf("Unable to start aries agentd, HTTP Inbound transport host not provided")
		return
	}
	opts = append(opts, defaults.WithInboundHTTPAddr(inboundHost))

	dbPath := os.Getenv(agentDBPathEnvKey)
	if dbPath != "" {
		opts = append(opts, defaults.WithStorePath(dbPath))
	}

	framework, err := aries.New(opts...)
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], failed to initialize framework :  %s", host, err)
	}

	ctx, err := framework.Context()
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], failed to get aries context :  %s", host, err)
	}

	// get all HTTP REST API handlers available for controller API
	restService, err := restapi.New(ctx)
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], failed to get rest service api :  %s", host, err)
	}
	handlers := restService.GetOperations()

	// register handlers
	router := mux.NewRouter()
	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting aries agentd on host [%s]", host)

	// start server on given port and serve using given handlers
	err = http.ListenAndServe(host, router)
	if err != nil {
		logger.Fatalf("Failed to start aries agentd on port [%s], cause:  %s", host, err)
	}
}
