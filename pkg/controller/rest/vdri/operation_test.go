/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
)

const sampleDIDName = "sampleDIDName"

//nolint:lll
const doc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:peer:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:peer:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:peer:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:peer:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ]
}`

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		require.Equal(t, 5, len(cmd.GetRESTHandlers()))
	})

	t.Run("test new command - error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error opening the store"),
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "new did store")
		require.Nil(t, cmd)
	})
}

func TestOperation_GetAPIHandlers(t *testing.T) {
	svc, err := New(&protocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestOperation_CreatePublicDID(t *testing.T) {
	t.Run("Successful Create public DID", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupHandler(t, svc, createPublicDIDPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path()+"?method=sidetree")
		require.NoError(t, err)

		response := createPublicDIDResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)
		require.NotEmpty(t, response.DID.ID)
		require.NotEmpty(t, response.DID.PublicKey)
		require.NotEmpty(t, response.DID.Service)
	})

	t.Run("Failed Create public DID", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupHandler(t, svc, createPublicDIDPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, nil, handler.Path())
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, vdri.InvalidRequestErrorCode, "", buf.Bytes())

		handler = lookupHandler(t, svc, createPublicDIDPath, http.MethodPost)
		buf, code, err = sendRequestToHandler(handler, nil, handler.Path()+"?-----")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, vdri.InvalidRequestErrorCode, "", buf.Bytes())
	})

	t.Run("Failed Create public DID, VDRI error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{CustomVDRI: &mockvdri.MockVDRIRegistry{CreateErr: fmt.Errorf("just-fail-it")}})
		require.NoError(t, err)
		require.NotNil(t, svc)
		handler := lookupHandler(t, svc, createPublicDIDPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, nil, handler.Path()+"?method=valid")
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, vdri.CreatePublicDIDError, "", buf.Bytes())
	})
}

func TestSaveDID(t *testing.T) {
	t.Run("test save did - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		didReq := vdri.DIDArgs{
			Document: vdri.Document{DID: json.RawMessage(doc)},
			Name:     sampleDIDName,
		}
		jsonStr, err := json.Marshal(didReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, saveDIDPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		// verify response
		require.NotEmpty(t, buf)
	})

	t.Run("test save did - error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var jsonStr = []byte(`{
			"name" : "sample"
		}`)

		handler := lookupHandler(t, cmd, saveDIDPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, vdri.SaveDIDErrorCode, "parse did doc", buf.Bytes())
	})
}

func TestGetDID(t *testing.T) {
	t.Run("test get did - success", func(t *testing.T) {
		s := make(map[string][]byte)
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = []byte(doc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		fmt.Println(base64.StdEncoding.EncodeToString([]byte("http://example.edu/credentials/1989")))

		handler := lookupHandler(t, cmd, getDIDPath, http.MethodGet)
		buf, err := getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/%s`,
			vdriDIDPath, base64.StdEncoding.EncodeToString([]byte("did:peer:21tDAKCERh95uGgKbJNHYp"))))
		require.NoError(t, err)

		response := documentRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
	})

	t.Run("test get vc - error", func(t *testing.T) {
		s := make(map[string][]byte)
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = []byte(doc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, getDIDPath, http.MethodGet)
		buf, code, err := sendRequestToHandler(handler, nil, fmt.Sprintf(`%s/%s`, vdriDIDPath, "abc"))
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, vdri.InvalidRequestErrorCode, "invalid id", buf.Bytes())
	})
}

func TestResolveDID(t *testing.T) {
	t.Run("test resolve did - success", func(t *testing.T) {
		didDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRIRegistryValue:    &mockvdri.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, resolveDIDPath, http.MethodGet)
		buf, err := getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/resolve/%s`,
			vdriDIDPath, base64.StdEncoding.EncodeToString([]byte("did:peer:21tDAKCERh95uGgKbJNHYp"))))
		require.NoError(t, err)

		response := documentRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
	})

	t.Run("test resolve did - error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, resolveDIDPath, http.MethodGet)
		buf, code, err := sendRequestToHandler(handler, nil, fmt.Sprintf(`%s/resolve/%s`, vdriDIDPath, "abc"))
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, vdri.InvalidRequestErrorCode, "invalid id", buf.Bytes())
	})
}

func TestGetDIDRecords(t *testing.T) {
	t.Run("test get did records", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		didReq := vdri.DIDArgs{
			Document: vdri.Document{DID: json.RawMessage(doc)},
			Name:     sampleDIDName,
		}
		jsonStr, err := json.Marshal(didReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, saveDIDPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		handler = lookupHandler(t, cmd, getDIDRecordsPath, http.MethodGet)
		buf, err = getSuccessResponseFromHandler(handler, nil, getDIDRecordsPath)
		require.NoError(t, err)

		var response didRecordResult
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.Equal(t, 1, len(response.Result))
	})
}

func lookupHandler(t *testing.T, op *Operation, path, method string) rest.Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == path && h.Method() == method {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

// getSuccessResponseFromHandler reads response from given http handle func.
// expects http status OK.
func getSuccessResponseFromHandler(handler rest.Handler, requestBody io.Reader,
	path string) (*bytes.Buffer, error) {
	response, status, err := sendRequestToHandler(handler, requestBody, path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: got %v, want %v",
			status, http.StatusOK)
	}

	return response, err
}

// sendRequestToHandler reads response from given http handle func.
func sendRequestToHandler(handler rest.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int, error) {
	// prepare request
	req, err := http.NewRequest(handler.Method(), path, requestBody)
	if err != nil {
		return nil, 0, err
	}

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code, nil
}

func verifyError(t *testing.T, expectedCode command.Code, expectedMsg string, data []byte) {
	// Parser generic error response
	errResponse := struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{}
	err := json.Unmarshal(data, &errResponse)
	require.NoError(t, err)

	// verify response
	require.EqualValues(t, expectedCode, errResponse.Code)
	require.NotEmpty(t, errResponse.Message)

	if expectedMsg != "" {
		require.Contains(t, errResponse.Message, expectedMsg)
	}
}
