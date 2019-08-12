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

	//build a mock cert pool
	cp := x509.NewCertPool()
	err := addCertsToCertPool(cp)
	require.NoError(t, err)

	// build a tls.Config instance to be used by the outbound transport
	tlsConfig := &tls.Config{
		RootCAs:      cp,
		Certificates: nil,
	}
	// create a new invalid Outbound transport instance
	_, err = NewOutbound()
	require.Error(t, err)
	require.EqualError(t, err, "Can't create an outbound transport without an HTTP client")

	// now create a new valid Outbound transport instance and test its Send() call
	ot, err := NewOutbound(WithOutboundTLSConfig(tlsConfig), WithOutboundTimeout(clientTimeout))
	require.NoError(t, err)
	require.NotNil(t, ot)

	// test Outbound transport's api
	// first with an empty url
	r, e := ot.Send("Hello World", "")
	require.Error(t, e)
	require.Empty(t, r)

	// now try a bad url
	r, e = ot.Send("Hello World", "https://badurl")
	require.Error(t, e)
	require.Empty(t, r)

	// and try with a 'bad' payload with a valid url..
	r, e = ot.Send("bad", serverURL)
	require.Error(t, e)
	require.Empty(t, r)

	// finally using a valid url
	r, e = ot.Send("Hello World", serverURL)
	require.NoError(t, e)
	require.NotEmpty(t, r)

}
