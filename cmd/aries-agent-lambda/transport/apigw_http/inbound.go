/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Boran Car <boran.car@gmail.com>. All Rights Reserved.
Copyright Christian Nuss <christian@scaffold.ly>, Founder, Scaffoldly LLC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package apigw_http

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

const (
	commContentType = "application/didcomm-envelope-enc"
	httpScheme      = "http"
)

// Probably hacky AF, but save a reference to the transport provider in memory
// Each function invocation should operate in its own memory space, so saving this contextually should be safe :fingers-crossed:
var (
	transportProvider transport.Provider
)

func NewInboundHandler() http.HandlerFunc {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processPOSTRequest(w, r, transportProvider)
	})

	// TODO: CORS
	return handler
}

func processPOSTRequest(w http.ResponseWriter, r *http.Request, prov transport.Provider) {
	if valid := validateHTTPMethod(w, r); !valid {
		return
	}

	if valid := validatePayload(r, w); !valid {
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Error reading request body: %s - returning Code: %d", err, http.StatusInternalServerError)
		http.Error(w, "Failed to read payload", http.StatusInternalServerError)

		return
	}

	unpackMsg, err := prov.Packager().UnpackMessage(body)
	if err != nil {
		log.Fatalf("failed to unpack msg: %s - returning Code: %d", err, http.StatusInternalServerError)
		http.Error(w, "failed to unpack msg", http.StatusInternalServerError)

		return
	}

	messageHandler := prov.InboundMessageHandler()

	err = messageHandler(unpackMsg)
	if err != nil {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/271 HTTP Response Codes based on errors
		//  from service
		log.Fatalf("incoming msg processing failed: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
}

// validatePayload validate and get the payload from the request.
func validatePayload(r *http.Request, w http.ResponseWriter) bool {
	if r.ContentLength == 0 { // empty payload should not be accepted
		http.Error(w, "Empty payload", http.StatusBadRequest)
		return false
	}

	return true
}

// validateHTTPMethod validate HTTP method and content-type.
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

func WithInboundHTTP(externalAddr string) aries.Option {
	return func(opts *aries.Aries) error {
		transport, _ := NewInbound(externalAddr)
		return aries.WithInboundTransport(transport)(opts)
	}
}

type Inbound struct {
	externalAddr string
}

func NewInbound(externalAddr string) (*Inbound, error) {
	if externalAddr == "" {
		return nil, errors.New("external addr is mandatory")
	}
	return &Inbound{
		externalAddr: externalAddr,
	}, nil
}

func (i *Inbound) Start(prov transport.Provider) error {
	transportProvider = prov

	return nil
}

func (i *Inbound) Stop() error {
	return nil
}

func (i *Inbound) Endpoint() string {
	return i.externalAddr
}
