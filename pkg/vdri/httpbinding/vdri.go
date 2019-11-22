/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

var logger = log.New("aries-framework/vdri/httpbinding")

const (
	pubKeyIndex1      = "#key-1"
	pubKeyController  = "controller"
	svcEndpointIndex1 = "#endpoint-1"
)

// VDRI via HTTP(s) endpoint
type VDRI struct {
	endpointURL string
	client      *http.Client
	accept      Accept
}

// Accept is method to accept did method
type Accept func(method string) bool

// New creates new DID Resolver
func New(endpointURL string, opts ...Option) (*VDRI, error) {
	vdri := &VDRI{client: &http.Client{}, accept: func(method string) bool { return true }}

	for _, opt := range opts {
		opt(vdri)
	}

	// Validate host
	_, err := url.ParseRequestURI(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("base URL invalid: %w", err)
	}

	vdri.endpointURL = endpointURL

	return vdri, nil
}

// Accept did method - attempt to resolve any method
func (v *VDRI) Accept(method string) bool {
	return v.accept(method)
}

// Store did doc
func (v *VDRI) Store(doc *did.Doc, by *[]vdriapi.ModifiedBy) error {
	logger.Warnf(" store not supported in http binding vdri")
	return nil
}

// Build did doc
// TODO separate this public DID create from httpbinding
//  and remove with request builder option [Issue #860]
func (v *VDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*did.Doc, error) {
	// Apply options
	docOpts := &vdriapi.CreateDIDOpts{}

	for _, opt := range opts {
		opt(docOpts)
	}

	publicKey := did.PublicKey{
		ID:         pubKeyIndex1,
		Type:       pubKey.Type,
		Controller: pubKeyController,
		Value:      []byte(pubKey.Value),
	}

	t := time.Now()

	didDoc := &did.Doc{
		Context:   []string{did.Context},
		PublicKey: []did.PublicKey{publicKey},
		Created:   &t,
		Updated:   &t,
	}

	if docOpts.ServiceType != "" {
		s := did.Service{
			ID:              svcEndpointIndex1,
			Type:            docOpts.ServiceType,
			ServiceEndpoint: docOpts.ServiceEndpoint,
		}

		if docOpts.ServiceType == vdriapi.DIDCommServiceType {
			s.RecipientKeys = []string{publicKey.ID}
			s.Priority = 0
		}

		didDoc.Service = []did.Service{s}
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %s", err)
	}

	var reqBody io.Reader
	if docOpts.RequestBuilder != nil {
		reqBody, err = docOpts.RequestBuilder(docBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to build request : %s", err)
		}
	} else {
		reqBody = bytes.NewReader(docBytes)
	}

	resDoc, err := v.sendCreateRequest(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to send create DID request: %s", err)
	}

	return resDoc, nil
}

// TODO add timeouts on external calls [Issue: #855]
func (v *VDRI) sendCreateRequest(req io.Reader) (*did.Doc, error) {
	httpReq, err := http.NewRequest(http.MethodPost, v.endpointURL, req)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response status '%d'", resp.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %s", err)
	}

	didDoc, err := did.ParseDocument(responseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public DID document: %s", err)
	}

	return didDoc, nil
}

// Close frees resources being maintained by vdri.
func (v *VDRI) Close() error {
	return nil
}

// Option configures the peer vdri
type Option func(opts *VDRI)

// WithTimeout option is for definition of HTTP(s) timeout value of DID Resolver
func WithTimeout(timeout time.Duration) Option {
	return func(opts *VDRI) {
		opts.client.Timeout = timeout
	}
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *VDRI) {
		opts.client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
}

// WithAccept option is for accept did method
func WithAccept(accept Accept) Option {
	return func(opts *VDRI) {
		opts.accept = accept
	}
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}
