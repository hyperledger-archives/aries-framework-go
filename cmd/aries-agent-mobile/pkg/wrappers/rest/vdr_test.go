/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdvdr "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	opvdr "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdr"
)

const (
	mockDocument = `{"did":{"@context":["https://w3id.org/did/v1","https://w3id.org/did/v2"],
"id":"did:peer:21tDAKCERh95uGgKbJNHYp","verificationMethod":[{"controller":"did:peer:123456789abcdefghi",
"id":"did:peer:123456789abcdefghi#keys-1","publicKeyBase58":"H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
"type":"Secp256k1VerificationKey2018"},{"controller":"did:peer:123456789abcdefghw",
"id":"did:peer:123456789abcdefghw#key2",
"publicKeyBase58":"long_pub_key","type":"RsaVerificationKey2018"}]}}`
	mockDIDReq = `{"id":"did:peer:21tDAKCERh95uGgKbJNHYp"}`
)

func getVDRController(t *testing.T) *VDR {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetVDRController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	v, ok := controller.(*VDR)
	require.Equal(t, ok, true)

	return v
}

func TestVDR_GetDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		reqData := mockDIDReq
		mockURL, err := parseURL(mockAgentURL, opvdr.GetDIDPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := mockDocument
		vdrController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := vdrController.GetDID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVDR_GetDIDRecords(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		reqData := emptyJSON

		mockResponse := `{"result":[{"name":"sampleDIDName","id":"did:peer:21tDAKCERh95uGgKbJNHYp"}]}`
		vdrController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + opvdr.GetDIDRecordsPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := vdrController.GetDIDRecords(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVDR_CreateDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		reqCreate := cmdvdr.CreateDIDRequest{Method: "test", DID: []byte(mockDocument)}

		reqData, err := json.Marshal(reqCreate)
		require.NoError(t, err)

		mockURL, err := parseURL(mockAgentURL, opvdr.CreateDIDPath, string(reqData))
		require.NoError(t, err, "failed to parse test url")

		mockResponse := mockDocument
		vdrController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: reqData}
		resp := vdrController.CreateDID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVDR_ResolveDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		reqData := mockDIDReq
		mockURL, err := parseURL(mockAgentURL, opvdr.ResolveDIDPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := mockDocument
		vdrController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := vdrController.ResolveDID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVDR_SaveDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		reqData := `{"did":{"@context":["https://w3id.org/did/v1","https://w3id.org/did/v2"],
"id":"did:peer:21tDAKCERh95uGgKbJNHYp","verificationMethod":[{"id":"did:peer:123456789abcdefghi#keys-1",
"type":"Secp256k1VerificationKey2018","controller":"did:peer:123456789abcdefghi",
"publicKeyBase58":"H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"},
{"id":"did:peer:123456789abcdefghw#key2","type":"RsaVerificationKey2018","controller":"did:peer:123456789abcdefghw",
"publicKeyPem":"pem_content_goes_here"}]},"name":"sampleDIDName"}`
		mockURL, err := parseURL(mockAgentURL, opvdr.SaveDIDPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		vdrController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := vdrController.SaveDID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
