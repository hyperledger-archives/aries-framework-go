/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

//go:generate testdata/scripts/openssl_env.sh testdata/scripts/generate_test_keys.sh

const (
	commContentType       = "application/didcomm-envelope-enc"
	commContentTypeLegacy = "application/ssi-agent-wire"
	httpScheme            = "http"
)

// outboundCommHTTPOpts holds options for the HTTP transport implementation of CommTransport
// it has an http.Client instance.
type outboundCommHTTPOpts struct {
	client *http.Client
}

// OutboundHTTPOpt is an outbound HTTP transport option.
type OutboundHTTPOpt func(opts *outboundCommHTTPOpts)

// WithOutboundHTTPClient option is for creating an Outbound HTTP transport using an http.Client instance.
func WithOutboundHTTPClient(client *http.Client) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client = client
	}
}

// WithOutboundTimeout option is for creating an Outbound HTTP transport using a client timeout value.
func WithOutboundTimeout(timeout time.Duration) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client.Timeout = timeout
	}
}

// WithOutboundTLSConfig option is for creating an Outbound HTTP transport using a tls.Config instance.
func WithOutboundTLSConfig(tlsConfig *tls.Config) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}
}

// OutboundHTTPClient represents the Outbound HTTP transport instance.
type OutboundHTTPClient struct {
	client *http.Client
}

// NewOutbound creates a new instance of Outbound HTTP transport to Post requests to other Agents.
// An http.Client or tls.Config options is mandatory to create a transport instance.
func NewOutbound(opts ...OutboundHTTPOpt) (*OutboundHTTPClient, error) {
	clOpts := &outboundCommHTTPOpts{}
	// Apply options
	for _, opt := range opts {
		opt(clOpts)
	}

	if clOpts.client == nil {
		return nil, errors.New("creation of outbound transport requires an HTTP client")
	}

	cs := &OutboundHTTPClient{
		client: clOpts.client,
	}

	return cs, nil
}

// Start starts outbound transport.
func (cs *OutboundHTTPClient) Start(prov transport.Provider) error {
	return nil
}

// Send sends a2a exchange data via HTTP (client side).
func (cs *OutboundHTTPClient) Send(data []byte, destination *service.Destination) (string, error) {
	uri, err := destination.ServiceEndpoint.URI()
	if err != nil {
		return "", fmt.Errorf("error getting ServiceEndpoint URI: %w", err)
	}

	resp, err := cs.client.Post(uri, commContentType, bytes.NewBuffer(data))
	if err != nil {
		logger.Errorf("posting DID envelope to agent failed [%s, %v]", destination.ServiceEndpoint, err)
		return "", err
	}

	var respData string

	if resp != nil {
		// handle response
		defer func() {
			e := resp.Body.Close()
			if e != nil {
				logger.Errorf("closing response body failed: %v", e)
			}
		}()

		buf := new(bytes.Buffer)

		_, e := buf.ReadFrom(resp.Body)
		if e != nil {
			return "", e
		}

		respData = buf.String()

		isStatusSuccess := resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK
		if !isStatusSuccess {
			logger.Errorf("didcomm failed : transport=http serviceEndpoint=%s status=%v errMsg=%s",
				destination.ServiceEndpoint, resp.Status, respData)

			return "", fmt.Errorf("received unsuccessful POST HTTP status from agent "+
				"[%s, %v %s]", destination.ServiceEndpoint, resp.Status, respData)
		}
	}

	return respData, nil
}

// AcceptRecipient checks if there is a connection for the list of recipient keys.
func (cs *OutboundHTTPClient) AcceptRecipient([]string) bool {
	return false
}

// Accept url.
func (cs *OutboundHTTPClient) Accept(url string) bool {
	return strings.HasPrefix(url, httpScheme)
}
