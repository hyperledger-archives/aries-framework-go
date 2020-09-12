package rest

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	opvdri "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdri"
)

const (
	mockDocument = `{"did":{"@context":["https://w3id.org/did/v1","https://w3id.org/did/v2"],
"id":"did:peer:21tDAKCERh95uGgKbJNHYp","publicKey":[{"controller":"did:peer:123456789abcdefghi",
"id":"did:peer:123456789abcdefghi#keys-1","publicKeyBase58":"H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
"type":"Secp256k1VerificationKey2018"},{"controller":"did:peer:123456789abcdefghw",
"id":"did:peer:123456789abcdefghw#key2",
"publicKeyBase58":"long_pub_key","type":"RsaVerificationKey2018"}]}}`
	mockDIDReq = `{"id":"did:peer:21tDAKCERh95uGgKbJNHYp"}`
)

func getVDRIController(t *testing.T) *VDRI {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetVDRIController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	v, ok := controller.(*VDRI)
	require.Equal(t, ok, true)

	return v
}

func TestVDRI_GetDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdriController := getVDRIController(t)

		reqData := mockDIDReq
		mockURL, err := parseURL(mockAgentURL, opvdri.GetDIDPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := mockDocument
		vdriController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := vdriController.GetDID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVDRI_GetDIDRecords(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdriController := getVDRIController(t)

		reqData := emptyJSON

		mockResponse := `{"result":[{"name":"sampleDIDName","id":"did:peer:21tDAKCERh95uGgKbJNHYp"}]}`
		vdriController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockAgentURL + opvdri.GetDIDRecordsPath,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := vdriController.GetDIDRecords(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVDRI_ResolveDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdriController := getVDRIController(t)

		reqData := mockDIDReq
		mockURL, err := parseURL(mockAgentURL, opvdri.ResolveDIDPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := mockDocument
		vdriController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodGet, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := vdriController.ResolveDID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}

func TestVDRI_SaveDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdriController := getVDRIController(t)

		reqData := `{"did":{"@context":["https://w3id.org/did/v1","https://w3id.org/did/v2"],
"id":"did:peer:21tDAKCERh95uGgKbJNHYp","publicKey":[{"id":"did:peer:123456789abcdefghi#keys-1",
"type":"Secp256k1VerificationKey2018","controller":"did:peer:123456789abcdefghi",
"publicKeyBase58":"H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"},
{"id":"did:peer:123456789abcdefghw#key2","type":"RsaVerificationKey2018","controller":"did:peer:123456789abcdefghw",
"publicKeyPem":"pem_content_goes_here"}]},"name":"sampleDIDName"}`
		mockURL, err := parseURL(mockAgentURL, opvdri.SaveDIDPath, reqData)
		require.NoError(t, err, "failed to parse test url")

		mockResponse := emptyJSON
		vdriController.httpClient = &mockHTTPClient{
			data:   mockResponse,
			method: http.MethodPost, url: mockURL,
		}

		req := &models.RequestEnvelope{Payload: []byte(reqData)}
		resp := vdriController.SaveDID(req)

		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t, mockResponse, string(resp.Payload))
	})
}
