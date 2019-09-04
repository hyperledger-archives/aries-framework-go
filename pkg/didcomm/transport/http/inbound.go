/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

var logger = log.New("aries-framework/transport")

// provider contains dependencies for the HTTP Handler creation and is typically created by using aries.Context()
type provider interface {
	InboundMessageHandler() transport.InboundMessageHandler
}

// NewInboundHandler will create a new handler to enforce Did-Comm HTTP transport specs
// then routes processing to the mandatory 'msgHandler' argument.
//
// Arguments:
// * 'msgHandler' is the handler function that will be executed with the inbound request payload.
//    Users of this library must manage the handling of all inbound payloads in this function.
func NewInboundHandler(prov provider) (http.Handler, error) {
	if prov == nil || prov.InboundMessageHandler() == nil {
		logger.Errorf("Error creating a new inbound handler: message handler function is nil")
		return nil, errors.New("Failed to create NewInboundHandler")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processPOSTRequest(w, r, prov.InboundMessageHandler())
	}), nil
}

func processPOSTRequest(w http.ResponseWriter, r *http.Request, messageHandler transport.InboundMessageHandler) {
	if valid := validateHTTPMethod(w, r); !valid {
		return
	}
	if valid := validatePayload(r, w); !valid {
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("Error reading request body: %s - returning Code: %d", err, http.StatusInternalServerError)
		http.Error(w, "Failed to read payload", http.StatusInternalServerError)
	}

	// TODO add Unpack(body) call here
	//...

	err = messageHandler(body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
}

// validatePayload validate and get the payload from the request
func validatePayload(r *http.Request, w http.ResponseWriter) bool {
	if r.ContentLength == 0 { // empty payload should not be accepted
		http.Error(w, "Empty payload", http.StatusBadRequest)
		return false
	}
	return true
}

// validateHTTPMethod validate HTTP method and content-type
func validateHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" {
		http.Error(w, "HTTP Method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	ct := r.Header.Get("Content-type")
	if ct != commContentType {
		http.Error(w, fmt.Sprintf("Unsupported Content-type \"%s\"", ct), http.StatusUnsupportedMediaType)
		return false
	}

	return true
}
