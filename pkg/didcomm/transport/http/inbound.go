/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/pkg/errors"
)

// MessageHandler is a function that handles the inbound request payload
// the payload will be unpacked prior to calling this function.
type MessageHandler func(payload []byte)

// NewInboundHandler will create a new handler to enforce Did-Comm HTTP transport specs
// then routes processing to the mandatory 'msgHandler' argument.
//
// Arguments:
// * 'msgHandler' is the handler function that will be executed with the inbound request payload.
//    Users of this library must manage the handling of all inbound payloads in this function.
func NewInboundHandler(msgHandler MessageHandler) (http.Handler, error) {
	if msgHandler == nil {
		log.Println("Error creating a new inbound handler: message handler function is nil")
		return nil, errors.New("Failed to create NewInboundHandler")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processPOSTRequest(w, r, msgHandler)
	}), nil
}

// TODO Log error message with a common logger library for aries-framework-go
func processPOSTRequest(w http.ResponseWriter, r *http.Request, messageHandler MessageHandler) {
	if valid := validateHTTPMethod(w, r); !valid {
		return
	}
	if valid := validatePayload(r, w); !valid {
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %s - returning Code: %d", err, http.StatusInternalServerError)
		http.Error(w, "Failed to read payload", http.StatusInternalServerError)
	}

	// TODO add Unpack(body) call here
	//...

	w.WriteHeader(http.StatusAccepted)

	go messageHandler(body)
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
