/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
package httpbinding

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithOutboundOpts(t *testing.T) {
	opt := WithTimeout(1 * time.Second)
	require.NotNil(t, opt)
	clOpts := &resolverOpts{}
	// opt.client is nil, so setting timeout should panic
	require.Panics(t, func() { opt(clOpts) })

	opt = WithTLSConfig(nil)
	require.NotNil(t, opt)
	clOpts = &resolverOpts{}
	// opt.client is nil, so setting TLS config should panic
	require.Panics(t, func() { opt(clOpts) })
}

func TestNew(t *testing.T) {
	var err error

	// OK with no options
	_, err = New("https://uniresolver.io/")
	require.NoError(t, err)

	// All options are applied
	i := 0
	_, err = New("https://uniresolver.io/",
		func(opts *resolverOpts) {
			i += 1 // nolint
		},
		func(opts *resolverOpts) {
			i += 2
		},
	)
	require.NoError(t, err)
	require.Equal(t, 1+2, i)

	// Invalid URL
	_, err = New("invalid url")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid base url")
}

func TestRead_DIDDoc(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		require.Equal(t, "/did:example:334455", req.URL.String())
		res.Header().Add("Content-type", "application/did+ld+json")
		res.WriteHeader(http.StatusOK)
		_, _ = res.Write([]byte("did doc body"))
	}))
	defer func() { testServer.Close() }()

	resolver, _ := New(testServer.URL)
	gotDocument, err := resolver.Read("did:example:334455")
	require.NoError(t, err)
	require.Equal(t, []byte("did doc body"), gotDocument)
}

func TestRead_DIDDocWithBasePath(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		require.Equal(t, "/document/did:example:334455", req.URL.String())
		res.Header().Add("Content-type", "application/did+ld+json")
		res.WriteHeader(http.StatusOK)
		_, _ = res.Write([]byte("did doc body"))
	}))
	defer func() { testServer.Close() }()

	resolver, _ := New(testServer.URL + "/document")
	gotDocument, err := resolver.Read("did:example:334455")
	require.NoError(t, err)
	require.Equal(t, []byte("did doc body"), gotDocument)
}

func TestRead_DIDDocWithBasePathWithSlashes(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		require.Equal(t, "/document/did:example:334455", req.URL.String())
		res.Header().Add("Content-type", "application/did+ld+json")
		res.WriteHeader(http.StatusOK)
		_, _ = res.Write([]byte("did doc body"))
	}))
	defer func() { testServer.Close() }()

	resolver, _ := New(testServer.URL + "/document/")
	gotDocument, err := resolver.Read("did:example:334455")
	require.NoError(t, err)
	require.Equal(t, []byte("did doc body"), gotDocument)
}

func TestRead_DIDDocNotFound(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		require.Equal(t, "/did:example:334455", req.URL.String())
		res.WriteHeader(http.StatusNotFound)
		_, _ = res.Write([]byte("did doc body"))
	}))
	defer func() { testServer.Close() }()

	resolver, _ := New(testServer.URL)
	_, err := resolver.Read("did:example:334455")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Input DID does not exist")
}

func TestRead_UnsupportedStatus(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusForbidden)
	}))
	defer func() { testServer.Close() }()

	resolver, _ := New(testServer.URL)
	_, err := resolver.Read("did:example:334455")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Unsupported response from DID Resolver with status code")
}

func TestRead_HTTPGetFailed(t *testing.T) {
	// HTTP GET failed
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusSeeOther)
	}))
	defer func() { testServer.Close() }()

	resolver, _ := New(testServer.URL)
	_, err := resolver.Read("did:example:334455")
	require.Error(t, err)
	require.Contains(t, err.Error(), "HTTP Get request failed")
}

func TestDIDResolver_Accept(t *testing.T) {
	res := &DIDResolver{}
	accepted := res.Accept("foo")
	require.True(t, accepted)
}
