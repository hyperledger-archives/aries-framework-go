/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

const (
	testDID    = "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
	testDomain = "https://identity.foundation"

	contextV1 = "https://identity.foundation/.well-known/did-configuration/v1"
)

func TestNew(t *testing.T) {
	t.Run("success - default options", func(t *testing.T) {
		c := New()
		require.NotNil(t, c)
		require.Len(t, c.didConfigOpts, 0)
	})

	t.Run("success - did config options provided", func(t *testing.T) {
		loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
			URL:     contextV1,
			Content: json.RawMessage(didCfgCtxV1),
		})
		require.NoError(t, err)

		c := New(WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))),
			WithHTTPClient(&http.Client{}))
		require.NotNil(t, c)
		require.Len(t, c.didConfigOpts, 2)
	})
}

func TestVerifyDIDAndDomain(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
		URL:     contextV1,
		Content: json.RawMessage(didCfgCtxV1),
	})
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(didCfg))),
				}, nil
			},
		}

		c := New(WithJSONLDDocumentLoader(loader), WithHTTPClient(httpClient))

		err := c.VerifyDIDAndDomain(testDID, testDomain)
		require.NoError(t, err)
	})

	t.Run("success", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(didCfg))),
				}, nil
			},
		}

		c := New(WithJSONLDDocumentLoader(loader), WithHTTPClient(httpClient))

		err := c.VerifyDIDAndDomain(testDID, testDomain)
		require.NoError(t, err)
	})

	t.Run("error - http client error", func(t *testing.T) {
		c := New(WithJSONLDDocumentLoader(loader))

		err := c.VerifyDIDAndDomain(testDID, "https://non-existent-abc.com")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"Get \"https://non-existent-abc.com/.well-known/did-configuration.json\": dial tcp: "+
				"lookup non-existent-abc.com: no such host")
	})

	t.Run("error - http request error", func(t *testing.T) {
		c := New(WithJSONLDDocumentLoader(loader))

		err := c.VerifyDIDAndDomain(testDID, ":invalid.com")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing protocol scheme")
	})

	t.Run("error - http status error", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte("data not found"))),
				}, nil
			},
		}

		c := New(WithJSONLDDocumentLoader(loader), WithHTTPClient(httpClient))

		err := c.VerifyDIDAndDomain(testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "endpoint https://identity.foundation/.well-known/did-configuration.json "+
			"returned status '404' and message 'data not found'")
	})

	t.Run("error - did configuration missing linked DIDs", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(didCfgNoLinkedDIDs))),
				}, nil
			},
		}

		c := New(WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))),
			WithHTTPClient(httpClient))

		err := c.VerifyDIDAndDomain(testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "did configuration: property 'linked_dids' is required ")
	})
}

func TestCloseResponseBody(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		closeResponseBody(&mockCloser{Err: fmt.Errorf("test error")})
	})
}

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

type mockCloser struct {
	Err error
}

func (c *mockCloser) Close() error {
	return c.Err
}

// nolint: lll
const didCfg = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "issuanceDate": "2020-12-04T14:08:28-06:00",
      "expirationDate": "2025-12-04T14:08:28-06:00",
      "type": [
        "VerifiableCredential",
        "DomainLinkageCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-12-04T20:08:28.540Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
      }
    }
  ]
}`

const didCfgNoLinkedDIDs = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1"
}`

// nolint: lll
const didCfgCtxV1 = `
{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "LinkedDomains": "https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains",
      "DomainLinkageCredential": "https://identity.foundation/.well-known/resources/did-configuration/#DomainLinkageCredential",
      "origin": "https://identity.foundation/.well-known/resources/did-configuration/#origin",
      "linked_dids": "https://identity.foundation/.well-known/resources/did-configuration/#linked_dids"
    }
  ]
}`
