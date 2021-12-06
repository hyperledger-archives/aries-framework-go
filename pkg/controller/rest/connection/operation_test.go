/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	command "github.com/hyperledger/aries-framework-go/pkg/controller/command/connection"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	didcomm "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
)

const (
	mockSignatureValue = "mock-did-rotation-signature"
	myDIDSuffix        = "myDID"
	myDID              = "did:peer:" + myDIDSuffix
	theirDID           = "did:peer:123456789abcdefghi"
	newDID             = "did:test:new"
)

func mockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	storeProv := mockstore.NewMockStoreProvider()

	prov := &mockprovider.Provider{
		StorageProviderValue:              storeProv,
		ProtocolStateStorageProviderValue: storeProv,
	}

	prov.VDRegistryValue = &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			switch didID {
			default:
				fallthrough
			case myDID:
				return &did.DocResolution{
					DIDDocument: mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, myDIDSuffix),
				}, nil
			case theirDID:
				return &did.DocResolution{
					DIDDocument: mockdiddoc.GetMockDIDDocWithKeyAgreements(t),
				}, nil
			}
		},
	}

	didStore, err := didstore.NewConnectionStore(prov)
	require.NoError(t, err)

	prov.DIDConnectionStoreValue = didStore

	prov.CryptoValue = &mockcrypto.Crypto{
		SignValue: []byte(mockSignatureValue),
	}

	prov.KMSValue = &mockkms.KeyManager{}

	didRotator, err := didrotate.New(prov)
	require.NoError(t, err)

	prov.DIDRotatorValue = *didRotator

	return prov
}

func TestNew(t *testing.T) {
	prov := mockProvider(t)

	op, err := New(prov)
	require.NoError(t, err)

	require.NotEmpty(t, op.GetRESTHandlers())

	prov.StorageProviderValue = &mockstore.MockStoreProvider{
		ErrOpenStoreHandle: fmt.Errorf("store error"),
	}

	op, err = New(prov)
	require.Error(t, err)
	require.Nil(t, op)
}

func TestOperation_CreateConnectionV2(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		prov := mockProvider(t)

		op, err := New(prov)
		require.NoError(t, err)

		h := handlerLookup(t, op, CreateConnectionV2Path)

		req := command.CreateConnectionRequest{
			MyDID:    myDID,
			TheirDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		body, code, err := sendRequestToHandler(h, bytes.NewReader(reqBytes), CreateConnectionV2Path)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)

		resp := command.IDMessage{}
		require.NoError(t, json.Unmarshal(body.Bytes(), &resp))

		lookup, err := connection.NewLookup(prov)
		require.NoError(t, err)

		// verify that connection was created
		conn, err := lookup.GetConnectionRecord(resp.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, resp.ConnectionID, conn.ConnectionID)
		require.Equal(t, myDID, conn.MyDID)
		require.Equal(t, theirDID, conn.TheirDID)
	})

	t.Run("fail", func(t *testing.T) {
		prov := mockProvider(t)

		op, err := New(prov)
		require.NoError(t, err)

		h := handlerLookup(t, op, CreateConnectionV2Path)

		req := command.CreateConnectionRequest{}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(h, bytes.NewReader(reqBytes), CreateConnectionV2Path)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
	})
}

func TestOperation_SetConnectionToDIDCommV2(t *testing.T) {
	connID := "test-connection-id"
	connPath := strings.ReplaceAll(SetConnectionToV2Path, "{id}", connID)
	badPath := strings.ReplaceAll(SetConnectionToV2Path, "{id}", "")

	t.Parallel()

	t.Run("success", func(t *testing.T) {
		prov := mockProvider(t)

		connStore, err := connection.NewRecorder(prov)
		require.NoError(t, err)

		require.NoError(t, connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			State:        connection.StateNameCompleted,
		}))

		op, err := New(prov)
		require.NoError(t, err)

		h := handlerLookup(t, op, SetConnectionToV2Path)

		req := command.IDMessage{
			ConnectionID: connID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(h, bytes.NewReader(reqBytes), connPath)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)

		// verify that connection was switched to didcomm v2
		conn, err := connStore.GetConnectionRecord(connID)
		require.NoError(t, err)
		require.Equal(t, didcomm.V2, conn.DIDCommVersion)
	})

	t.Run("fail getting ID from path", func(t *testing.T) {
		prov := mockProvider(t)

		op, err := New(prov)
		require.NoError(t, err)

		reqBytes := []byte("{}")

		rr := httptest.NewRecorder()

		op.SetConnectionToDIDCommV2(rr, httptest.NewRequest(
			http.MethodPost, badPath, bytes.NewReader(reqBytes)))

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("fail in command handle", func(t *testing.T) {
		prov := mockProvider(t)

		op, err := New(prov)
		require.NoError(t, err)

		h := handlerLookup(t, op, SetConnectionToV2Path)

		reqBytes := []byte("{}")

		_, code, err := sendRequestToHandler(h, bytes.NewReader(reqBytes), connPath)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
	})
}

func TestOperation_RotateDID(t *testing.T) {
	connID := "test-connection-id"
	connPath := strings.ReplaceAll(RotateDIDPath, "{id}", connID)
	badPath := strings.ReplaceAll(RotateDIDPath, "{id}", "")

	t.Parallel()

	t.Run("success", func(t *testing.T) {
		prov := mockProvider(t)

		connStore, err := connection.NewRecorder(prov)
		require.NoError(t, err)

		require.NoError(t, connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			MyDID:        myDID,
			TheirDID:     theirDID,
			State:        connection.StateNameCompleted,
		}))

		op, err := New(prov)
		require.NoError(t, err)

		h := handlerLookup(t, op, RotateDIDPath)

		req := command.RotateDIDRequest{
			ID:     connID,
			KID:    myDID + "#key-2",
			NewDID: newDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		_, code, err := sendRequestToHandler(h, bytes.NewReader(reqBytes), connPath)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)

		// verify that connection was switched to didcomm v2
		conn, err := connStore.GetConnectionRecord(connID)
		require.NoError(t, err)
		require.Equal(t, newDID, conn.MyDID)
	})

	t.Run("fail getting ID from path", func(t *testing.T) {
		prov := mockProvider(t)

		op, err := New(prov)
		require.NoError(t, err)

		reqBytes := []byte("{}")

		rr := httptest.NewRecorder()

		op.RotateDID(rr, httptest.NewRequest(
			http.MethodPost, badPath, bytes.NewReader(reqBytes)))

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("fail in command handler", func(t *testing.T) {
		prov := mockProvider(t)

		op, err := New(prov)
		require.NoError(t, err)

		h := handlerLookup(t, op, RotateDIDPath)

		reqBytes := []byte("{}")

		_, code, err := sendRequestToHandler(h, bytes.NewReader(reqBytes), connPath)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
	})
}

func handlerLookup(t *testing.T, op *Operation, lookup string) rest.Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
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
