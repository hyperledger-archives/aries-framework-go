/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdvdr "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
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

		mockResponse := mockDocument
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdrController.handlers[cmdvdr.GetDIDCommandMethod] = fakeHandler.exec

		payload := mockDIDReq

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := vdrController.GetDID(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestVDR_GetDIDRecords(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		mockResponse := `{"result":[{"name":"sampleDIDName","id":"did:peer:21tDAKCERh95uGgKbJNHYp"}]}`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdrController.handlers[cmdvdr.GetDIDsCommandMethod] = fakeHandler.exec

		payload := emptyJSON

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := vdrController.GetDIDRecords(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestVDR_CreateDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		mockResponse := mockDocument
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdrController.handlers[cmdvdr.CreateDIDCommandMethod] = fakeHandler.exec

		reqCreate := cmdvdr.CreateDIDRequest{Method: "test", DID: []byte(mockDocument)}

		reqBytes, err := json.Marshal(reqCreate)
		require.NoError(t, err)

		req := &models.RequestEnvelope{Payload: reqBytes}
		resp := vdrController.CreateDID(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestVDR_ResolveDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		mockResponse := mockDocument
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdrController.handlers[cmdvdr.ResolveDIDCommandMethod] = fakeHandler.exec

		payload := mockDIDReq

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := vdrController.ResolveDID(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestVDR_SaveDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdrController := getVDRController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdrController.handlers[cmdvdr.SaveDIDCommandMethod] = fakeHandler.exec

		payload := `{"did":{"@context":["https://w3id.org/did/v1","https://w3id.org/did/v2"],
"id":"did:peer:21tDAKCERh95uGgKbJNHYp","verificationMethod":[{"id":"did:peer:123456789abcdefghi#keys-1",
"type":"Secp256k1VerificationKey2018","controller":"did:peer:123456789abcdefghi",
"publicKeyBase58":"H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"},
{"id":"did:peer:123456789abcdefghw#key2","type":"RsaVerificationKey2018","controller":"did:peer:123456789abcdefghw",
"publicKeyPem":"pem_content_goes_here"}]},"name":"sampleDIDName"}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := vdrController.SaveDID(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
