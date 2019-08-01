/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"time"

	errors "golang.org/x/xerrors"
)

//go:generate testdata/scripts/openssl_env.sh testdata/scripts/generate_test_keys.sh

const commContentType = "application/didcomm-envelope-enc"

// outboundCommHTTPOpts holds options for the HTTP transport implementation of CommTransport
// it has an http.Client instance
type outboundCommHTTPOpts struct {
	client *http.Client
}

// OutboundHTTPOpt is an outbound HTTP transport option
type OutboundHTTPOpt func(opts *outboundCommHTTPOpts)

// WithOutboundHTTPClient option is for creating an Outbound HTTP transport using an http.Client instance
func WithOutboundHTTPClient(client *http.Client) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client = client
	}
}

// WithOutboundTimeout option is for creating an Outbound HTTP transport using a client timeout value
func WithOutboundTimeout(timeout time.Duration) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client.Timeout = timeout
	}
}

// WithOutboundTLSConfig option is for creating an Outbound HTTP transport using a tls.Config instance
func WithOutboundTLSConfig(tlsConfig *tls.Config) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}
}

// OutboundHTTPClient represents the Outbound HTTP transport instance
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
		return nil, errors.New("Can't create an outbound transport without an HTTP client")
	}

	cs := &OutboundHTTPClient{
		client: clOpts.client,
	}
	return cs, nil
}

// Send sends a2a exchange data via HTTP (client side)
func (cs *OutboundHTTPClient) Send(data string, url string) (string, error) {
	resp, err := cs.client.Post(url, commContentType, bytes.NewBuffer([]byte(data)))
	if err != nil {
		logger.Errorf("HTTP Transport - Error posting did envelope to agent at [%s]: %v", url, err)
		return "", err
	}

	var respData string
	if resp != nil {
		isStatusSuccess := resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK
		if !isStatusSuccess {
			return "", errors.Errorf("Warning - Received non success POST HTTP status from agent at [%s]: status : %v", url, resp.Status)
		}
		// handle response
		defer func() {
			e := resp.Body.Close()
			if e != nil {
				logger.Errorf("HTTP Transport - Error closing response body: %v", e)
			}
		}()
		buf := new(bytes.Buffer)
		_, e := buf.ReadFrom(resp.Body)
		if e != nil {
			return "", e
		}
		respData = buf.String()
	}
	return respData, nil
}
