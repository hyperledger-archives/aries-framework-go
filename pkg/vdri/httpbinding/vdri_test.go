/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
)

func TestVDRI_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New("/did:example:334455")
		require.NoError(t, err)
		require.NoError(t, v.Close())
	})
}

func TestVDRI_Build(t *testing.T) {
	pubKey := &vdriapi.PubKey{Type: "sample-type", Value: "sample-value"}

	const svcEndPoint = "http://sample-svc:8080"

	newDidDoc, err := (&vdri.MockVDRIRegistry{}).Create("test")

	require.NoError(t, err)

	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Add("Content-type", "application/json")
		res.WriteHeader(http.StatusOK)
		b, e := newDidDoc.JSONBytes()
		require.NoError(t, e)
		_, e = res.Write(b)
		require.NoError(t, e)
	}))

	defer testServer.Close()

	t.Run("test HTTP Binding VDRI build with default opts", func(t *testing.T) {
		resolver, err := New(testServer.URL)
		require.NoError(t, err)
		require.NotNil(t, resolver)

		result, err := resolver.Build(pubKey)
		require.NoError(t, err)
		require.NotEmpty(t, result)
		require.NoError(t, err)
		require.Equal(t, newDidDoc.ID, result.ID)
		require.Equal(t, newDidDoc.PublicKey, result.PublicKey)
	})

	t.Run("test HTTP Binding VDRI build with request builder opts", func(t *testing.T) {
		resolver, err := New(testServer.URL)
		require.NoError(t, err)
		require.NotNil(t, resolver)

		didBuilt, err := resolver.Build(pubKey, vdriapi.WithServiceType(vdriapi.DIDCommServiceType),
			vdriapi.WithServiceEndpoint(svcEndPoint),
			vdriapi.WithRequestBuilder(
				func(b []byte) (io.Reader, error) {
					return bytes.NewReader(b), nil
				}))
		require.NoError(t, err)
		require.Equal(t, newDidDoc.ID, didBuilt.ID)
		require.Equal(t, newDidDoc.PublicKey, didBuilt.PublicKey)
	})

	t.Run("test HTTP Binding VDRI build with request builder errors", func(t *testing.T) {
		const sampleErr = "sample-error"
		resolver, err := New("localhost:8080")
		require.NoError(t, err)
		require.NotNil(t, resolver)

		didBuilt, err := resolver.Build(pubKey, vdriapi.WithServiceType(vdriapi.DIDCommServiceType),
			vdriapi.WithServiceEndpoint(svcEndPoint),
			vdriapi.WithRequestBuilder(
				func(b []byte) (io.Reader, error) {
					return nil, fmt.Errorf(sampleErr)
				}))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErr)
		require.Nil(t, didBuilt)

		didBuilt, err = resolver.Build(pubKey, vdriapi.WithServiceType(vdriapi.DIDCommServiceType),
			vdriapi.WithServiceEndpoint(svcEndPoint),
			vdriapi.WithRequestBuilder(
				func(b []byte) (io.Reader, error) {
					return bytes.NewReader([]byte("-----")), nil
				}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send request")
		require.Nil(t, didBuilt)
	})

	t.Run("test HTTP Binding VDRI build with send create-request errors", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.Header().Add("Content-type", "application/json")

			reqURI := req.URL.String()
			fmt.Println("reqURI", reqURI)

			if reqURI == "/status400" {
				res.WriteHeader(http.StatusBadRequest)
				return
			}
			res.WriteHeader(http.StatusOK)
		}))

		defer func() { testServer.Close() }()

		allTests := []struct {
			reqURI string
			errMsg string
		}{
			{"/status400", "got unexpected response status"},
			{"/ss", " validation of DID doc failed"},
		}

		for _, test := range allTests {
			resolver, err := New(testServer.URL + test.reqURI)
			require.NoError(t, err)
			require.NotNil(t, resolver)

			didBuilt, err := resolver.Build(pubKey, vdriapi.WithServiceType(vdriapi.DIDCommServiceType),
				vdriapi.WithServiceEndpoint(svcEndPoint),
				vdriapi.WithRequestBuilder(
					func(b []byte) (io.Reader, error) {
						return bytes.NewReader(b), nil
					}))
			require.Error(t, err)
			require.Contains(t, err.Error(), test.errMsg)
			require.Nil(t, didBuilt)
		}
	})
}
