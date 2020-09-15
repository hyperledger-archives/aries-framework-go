/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	opverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
)

//nolint:lll
const (
	mockVC = `{
  "@context":[
     "https://www.w3.org/2018/credentials/v1",
	  "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "id":"http://example.edu/credentials/1989",
  "type":"VerifiableCredential",
  "credentialSubject":{
     "id":"did:example:iuajk1f712ebc6f1c276e12ec21"
  },
  "issuer":{
     "id":"did:example:09s12ec712ebc6f1c671ebfeb1f",
     "name":"Example University"
  },
  "issuanceDate":"2020-01-01T10:54:01Z",
  "credentialStatus":{
     "id":"https://example.gov/status/65",
     "type":"CredentialStatusList2017"
  }
}`
	mockSignedVC             = `{"@context":["https://www.w3.org/2018/credentials/v1","https://trustbloc.github.io/context/vc/examples-v1.jsonld"],"credentialStatus":{"id":"https://example.gov/status/65","type":"CredentialStatusList2017"},"credentialSubject":"did:example:iuajk1f712ebc6f1c276e12ec21","id":"http://example.edu/credentials/1989","issuanceDate":"2020-01-01T10:54:01Z","issuer":{"id":"did:example:09s12ec712ebc6f1c671ebfeb1f","name":"Example University"},"proof":{"created":"2020-07-13T09:25:45.843216-04:00","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..","proofPurpose":"assertionMethod","type":"Ed25519Signature2018","verificationMethod":"did:peer:123456789abcdefghi#keys-1"},"type":"VerifiableCredential"}`
	mockPresentationResponse = `
{
	"verifiablePresentation": {
		"@context": [
			"https://www.w3.org/2018/credentials/v1"
		],
		"holder": "did:peer:123456789abcdefghi#inbox",
		"proof": {
			"created": "2020-07-10T15:53:25.157489-04:00",
			"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..",
			"proofPurpose": "authentication",
			"type": "Ed25519Signature2018",
			"verificationMethod": "did:peer:123456789abcdefghi#keys-1"
		},
		"type": "VerifiablePresentation",
		"verifiableCredential": [
			{
				"@context": [
					"https://www.w3.org/2018/credentials/v1",
					"https://trustbloc.github.io/context/vc/examples-v1.jsonld"
				],
				"credentialStatus": {
					"id": "https://example.gov/status/65",
					"type": "CredentialStatusList2017"
				},
				"credentialSubject": "did:example:iuajk1f712ebc6f1c276e12ec21",
				"id": "http://example.edu/credentials/1989",
				"issuanceDate": "2020-01-01T10:54:01Z",
				"issuer": {
					"id": "did:example:09s12ec712ebc6f1c671ebfeb1f",
					"name": "Example University"
				},
				"type": "VerifiableCredential"
			}
		]
	}
}`
	mockCredentialName   = "mock_credential"
	mockPresentationName = "mock_vp_name"
	mockCredentialID     = "http://example.edu/credentials/1989"
	mockPresentationID   = "http://example.edu/presentations/1989"
	mockVP               = `{"verifiablePresentation":{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"type":["VerifiablePresentation"],"id":"http://example.edu/presentations/1989","verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"credentialSchema":[],"credentialStatus":{"id":"http://issuer.vc.rest.example.com:8070/status/1","type":"CredentialStatusList2017"},"credentialSubject":{"degree":{"degree":"MIT","type":"BachelorDegree"},"id":"did:example:ebfeb1f712ebc6f1c276e12ec21","name":"Jayden Doe","spouse":"did:example:c276e12ec21ebfeb1f712ebc6f1"},"id":"https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3","issuanceDate":"2020-03-16T22:37:26.544Z","issuer":{"id":"did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg","name":"alice_ca31684e-6cbb-40f9-b7e6-87e1ab5661ae"},"proof":{"created":"2020-04-08T21:19:02Z","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..yGHHYmRp4mWd918SDSzmBDs8eq-SX7WPl8moGB8oJeSqEMmuEiI81D4s5-BPWGmKy3VlCsKJxYrTNqrEGJpNAQ","proofPurpose":"assertionMethod","type":"Ed25519Signature2018","verificationMethod":"did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"},"type":["VerifiableCredential","UniversityDegreeCredential"]}]},"name":"sampleVpName"}`
	mockDID              = "did:peer:123456789abcdefghi#inbox"
	mockAgentURL         = "http://example.com"
	emptyJSON            = `{}`
)

func getAgent() (*Aries, error) {
	opts := &config.Options{AgentURL: mockAgentURL}
	return NewAries(opts)
}

func getVerifiableController(t *testing.T) *Verifiable {
	a, err := getAgent()
	require.NoError(t, err)
	require.NotNil(t, a)

	vc, err := a.GetVerifiableController()
	require.NoError(t, err)
	require.NotNil(t, vc)

	v, ok := vc.(*Verifiable)
	require.Equal(t, ok, true)

	return v
}

func parseURL(agentURL, operationPath, payload string) (string, error) { //nolint:unparam
	return embedParams(agentURL+operationPath, []byte(payload))
}

func TestVerifiable_ValidateCredential(t *testing.T) {
	t.Run("test it preforms a validates credential request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := emptyJSON
		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opverifiable.ValidateCredentialPath,
		}

		reqData := fmt.Sprintf(`{"verifiableCredential": %s}`, strconv.Quote(mockVC))
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.ValidateCredential(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_SaveCredential(t *testing.T) {
	t.Run("test it performs a save credential request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := emptyJSON
		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opverifiable.SaveCredentialPath,
		}

		reqData := fmt.Sprintf(`{"verifiableCredential": %s, "name": "%s"}`,
			strconv.Quote(mockVC), mockCredentialName)
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.SaveCredential(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_SavePresentation(t *testing.T) {
	t.Run("test it performs a save presentation request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := emptyJSON
		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opverifiable.SavePresentationPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(mockVP)}
		resp := v.SavePresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_GetCredential(t *testing.T) {
	t.Run("test it performs a get credential request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := fmt.Sprintf(`{"verifiableCredential": %s}`, strconv.Quote(mockVC))
		reqData := fmt.Sprintf(`{"id":"%s"}`, mockCredentialID)

		mockURL, err := parseURL(mockAgentURL, opverifiable.GetCredentialPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.GetCredential(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_SignCredential(t *testing.T) {
	t.Run("test it performs a sign credential request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := fmt.Sprintf(`{"verifiableCredential": %s}`, strconv.Quote(mockSignedVC))
		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opverifiable.SignCredentialsPath,
		}

		reqData := fmt.Sprintf(`{"credential": %s, "did": "%s", "signatureType": "%s"}`,
			strconv.Quote(mockVC), mockDID, cmdverifiable.Ed25519Signature2018)
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.SignCredential(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_GetPresentation(t *testing.T) {
	t.Run("test it performs a get presentation request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := fmt.Sprintf(`{"verifiablePresentation": %s}`, strconv.Quote(mockVP))
		reqData := fmt.Sprintf(`{"id":"%s"}`, mockPresentationID)

		mockURL, err := parseURL(mockAgentURL, opverifiable.GetPresentationPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		v.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodGet, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.GetPresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_GetCredentialByName(t *testing.T) {
	t.Run("test it performs a get credential by name request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := fmt.Sprintf(`{"name": %s, "id": %s}`, mockCredentialName, mockCredentialID)
		reqData := fmt.Sprintf(`{"name":"%s"}`, mockCredentialName)

		mockURL, err := parseURL(mockAgentURL, opverifiable.GetCredentialByNamePath, reqData)
		require.NoError(t, err, "failed to parse test url")

		v.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodGet, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.GetCredentialByName(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_GetCredentials(t *testing.T) {
	t.Run("test it performs a get credentials request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := fmt.Sprintf(`{"result": [{"name": "%s", "id":" %s"}, {"name": "%s"", "id": "%s""}]`,
			mockCredentialName, mockCredentialID, mockCredentialName, mockCredentialID)
		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + opverifiable.GetCredentialsPath,
		}

		reqData := "{}"
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.GetCredentials(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_GetPresentations(t *testing.T) {
	t.Run("test it performs a get presentations request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := fmt.Sprintf(`{"result": [{"name": "%s", "id":" %s"}, {"name": "%s"", "id": "%s""}]`,
			mockPresentationName, mockPresentationID, mockPresentationName, mockPresentationID)
		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + opverifiable.GetPresentationsPath,
		}

		req := &models.RequestEnvelope{Payload: []byte("{}")}
		resp := v.GetPresentations(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_GeneratePresentation(t *testing.T) {
	t.Run("test it performs a generate presentation request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := mockPresentationResponse
		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opverifiable.GeneratePresentationPath,
		}

		credList := fmt.Sprintf(`[%s, %s]`, mockVC, mockVC)
		reqData := fmt.Sprintf(`{"verifiableCredential": %s, "did": "%s", "signatureType": "%s"}`,
			credList, mockDID, cmdverifiable.Ed25519Signature2018)
		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.GeneratePresentation(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_GeneratePresentationByID(t *testing.T) {
	t.Run("test it performs a generate presentation by id request", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := mockPresentationResponse
		v.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockAgentURL + opverifiable.GeneratePresentationByIDPath,
		}

		credList := fmt.Sprintf(`[%s, %s]`, mockVC, mockVC)
		reqData := fmt.Sprintf(`{"verifiableCredential": %s, "did": "%s", "signatureType": "%s"}`,
			credList, mockDID, cmdverifiable.Ed25519Signature2018)

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.GeneratePresentationByID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_RemoveCredentialByName(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := ``
		reqData := fmt.Sprintf(`{"name":"%s"}`, mockCredentialName)

		mockURL, err := parseURL(mockAgentURL, opverifiable.RemoveCredentialByNamePath, reqData)
		require.NoError(t, err, "failed to parse test url")

		v.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.RemoveCredentialByName(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVerifiable_RemovePresentationByName(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		v := getVerifiableController(t)

		mockResponse := ``
		reqData := fmt.Sprintf(`{"name":"%s"}`, mockCredentialName)

		mockURL, err := parseURL(mockAgentURL, opverifiable.RemovePresentationByNamePath, reqData)
		require.NoError(t, err, "failed to parse test url")

		v.httpClient = &mockHTTPClient{data: mockResponse, method: http.MethodPost, url: mockURL}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := v.RemovePresentationByName(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
