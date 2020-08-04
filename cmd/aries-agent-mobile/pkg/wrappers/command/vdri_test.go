package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdvdri "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
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

		mockResponse := mockDocument
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdriController.handlers[cmdvdri.GetDIDCommandMethod] = fakeHandler.exec

		payload := mockDIDReq

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := vdriController.GetDID(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestVDRI_GetDIDRecords(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdriController := getVDRIController(t)

		mockResponse := `{"result":[{"name":"sampleDIDName","id":"did:peer:21tDAKCERh95uGgKbJNHYp"}]}`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdriController.handlers[cmdvdri.GetDIDsCommandMethod] = fakeHandler.exec

		payload := emptyResponse

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := vdriController.GetDIDRecords(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestVDRI_ResolveDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdriController := getVDRIController(t)

		mockResponse := mockDocument
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdriController.handlers[cmdvdri.ResolveDIDCommandMethod] = fakeHandler.exec

		payload := mockDIDReq

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := vdriController.ResolveDID(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestVDRI_SaveDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vdriController := getVDRIController(t)

		mockResponse := emptyResponse
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		vdriController.handlers[cmdvdri.SaveDIDCommandMethod] = fakeHandler.exec

		payload := `{"did":{"@context":["https://w3id.org/did/v1","https://w3id.org/did/v2"],
"id":"did:peer:21tDAKCERh95uGgKbJNHYp","publicKey":[{"id":"did:peer:123456789abcdefghi#keys-1",
"type":"Secp256k1VerificationKey2018","controller":"did:peer:123456789abcdefghi",
"publicKeyBase58":"H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"},
{"id":"did:peer:123456789abcdefghw#key2","type":"RsaVerificationKey2018","controller":"did:peer:123456789abcdefghw",
"publicKeyPem":"pem_content_goes_here"}]},"name":"sampleDIDName"}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := vdriController.SaveDID(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
