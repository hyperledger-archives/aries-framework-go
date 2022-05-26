/*
	Copyright SecureKey Technologies Inc. All Rights Reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

func TestWithOutboundOpts(t *testing.T) {
	opt := WithOutboundHTTPClient(nil)
	require.NotNil(t, opt)

	clOpts := &outboundCommHTTPOpts{}
	opt(clOpts)

	opt = WithOutboundTimeout(clientTimeout)
	require.NotNil(t, opt)

	clOpts = &outboundCommHTTPOpts{}
	// opt.client is nil, so setting timeout should panic
	require.Panics(t, func() { opt(clOpts) })

	opt = WithOutboundTLSConfig(nil)
	require.NotNil(t, opt)

	clOpts = &outboundCommHTTPOpts{}
	opt(clOpts)
}

func TestOutboundHTTPTransport(t *testing.T) {
	// prepare http server
	server := startMockServer(mockHTTPHandler{})

	port := getServerPort(server)
	serverURL := fmt.Sprintf("https://localhost:%d", port)

	defer func() {
		err := server.Close()
		if err != nil {
			t.Fatalf("Failed to stop server: %s", err)
		}
	}()

	// build a mock cert pool
	cp := x509.NewCertPool()
	err := addCertsToCertPool(cp)
	require.NoError(t, err)

	// build a tls.Config instance to be used by the outbound transport
	tlsConfig := &tls.Config{ //nolint:gosec

		RootCAs:      cp,
		Certificates: nil,
	}
	// create a new invalid Outbound transport instance
	_, err = NewOutbound()
	require.Error(t, err)
	require.EqualError(t, err, "creation of outbound transport requires an HTTP client")

	// now create a new valid Outbound transport instance and test its Send() call
	ot, err := NewOutbound(WithOutboundTLSConfig(tlsConfig), WithOutboundTimeout(clientTimeout))
	require.NoError(t, err)
	require.NotNil(t, ot)

	// test Outbound transport's api
	// first with an empty url
	r, e := ot.Send([]byte("Hello World"), prepareDestination("serverURL"))
	require.Error(t, e)
	require.Empty(t, r)

	// now try a bad url
	r, e = ot.Send([]byte("Hello World"), prepareDestination("https://badurl"))
	require.Error(t, e)
	require.Empty(t, r)

	// and try with a 'bad' payload with a valid url..
	r, e = ot.Send([]byte("bad"), prepareDestination(serverURL))
	require.Error(t, e)
	require.Empty(t, r)
	require.Contains(t, e.Error(), "received unsuccessful POST HTTP status from agent")

	// finally using a valid url
	r, e = ot.Send([]byte("Hello World"), prepareDestination(serverURL))
	require.NoError(t, e)
	require.NotEmpty(t, r)

	require.True(t, ot.Accept("http://example.com"))
	require.False(t, ot.Accept("123:22"))
}

func prepareDestination(endPoint string) *service.Destination {
	return &service.Destination{
		ServiceEndpoint: model.NewDIDCommV1Endpoint(endPoint),
	}
}
