/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
)

const (
	mockSignatureValue = "mock-did-rotation-signature"
	myDIDSuffix        = "myDID"
	myDID              = "did:peer:" + myDIDSuffix
	theirDID           = "did:peer:123456789abcdefghi"
	connID             = "test-connection-id"
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

	didRotator, err := middleware.New(prov)
	require.NoError(t, err)

	prov.DIDRotatorValue = *didRotator

	prov.KeyTypeValue = kms.ED25519
	prov.KeyAgreementTypeValue = kms.X25519ECDHKW

	return prov
}

func TestNew(t *testing.T) {
	prov := mockProvider(t)

	cmd, err := New(prov)
	require.NoError(t, err)
	require.NotEmpty(t, cmd.GetHandlers())

	expectErr := fmt.Errorf("expected error")

	prov.StorageProviderValue = &mockstore.MockStoreProvider{ErrOpenStoreHandle: expectErr}

	_, err = New(prov)
	require.ErrorIs(t, err, expectErr)
}

func TestCommand_CreateConnectionV2(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := CreateConnectionRequest{
			MyDID:    myDID,
			TheirDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := cmd.CreateConnectionV2(&b, bytes.NewReader(reqBytes))
		require.NoError(t, cmdErr)

		response := IDMessage{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEqual(t, "", response.ConnectionID)
	})

	t.Run("fail: parse request", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := cmd.CreateConnectionV2(&b, bytes.NewReader([]byte("bad message")))
		require.Error(t, cmdErr)
	})

	t.Run("fail: missing myDID", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := CreateConnectionRequest{
			TheirDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := cmd.CreateConnectionV2(&b, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyMyDID)
	})

	t.Run("fail: missing theirDID", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := CreateConnectionRequest{
			MyDID: myDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := cmd.CreateConnectionV2(&b, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyTheirDID)
	})

	t.Run("fail: error in client execution", func(t *testing.T) {
		prov := mockProvider(t)

		expectErr := "expected error"

		prov.VDRegistryValue = &mockvdr.MockVDRegistry{ResolveErr: fmt.Errorf(expectErr)}

		cmd, err := New(prov)
		require.NoError(t, err)

		req := CreateConnectionRequest{
			MyDID:    myDID,
			TheirDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := cmd.CreateConnectionV2(&b, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), expectErr)
	})
}

func TestCommand_SetConnectionToDIDCommV2(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		prov := mockProvider(t)

		connStore, err := connection.NewRecorder(prov)
		require.NoError(t, err)

		require.NoError(t, connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			State:        connection.StateNameCompleted,
		}))

		cmd, err := New(prov)
		require.NoError(t, err)

		req := IDMessage{
			ConnectionID: connID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		cmdErr := cmd.SetConnectionToDIDCommV2(nil, bytes.NewReader(reqBytes))
		require.NoError(t, cmdErr)
	})

	t.Run("fail: parse request", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		cmdErr := cmd.SetConnectionToDIDCommV2(nil, bytes.NewReader([]byte("bad message")))
		require.Error(t, cmdErr)
	})

	t.Run("fail: missing connection ID", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := IDMessage{}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		cmdErr := cmd.SetConnectionToDIDCommV2(nil, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyConnID)
	})

	t.Run("fail: error in client execution", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := IDMessage{
			ConnectionID: connID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		cmdErr := cmd.SetConnectionToDIDCommV2(nil, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Equal(t, SetToDIDCommV2ErrorCode, cmdErr.Code())
	})
}

func TestCommand_RotateDID(t *testing.T) {
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

		cmd, err := New(prov)
		require.NoError(t, err)

		req := RotateDIDRequest{
			ID:     connID,
			KID:    myDID + "#key-2",
			NewDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		cmdErr := cmd.RotateDID(rw, bytes.NewReader(reqBytes))
		require.NoError(t, cmdErr)

		resp := RotateDIDResponse{}

		err = json.NewDecoder(rw.Result().Body).Decode(&resp)
		require.NoError(t, err)

		require.Equal(t, theirDID, resp.NewDID)
	})

	t.Run("success: with peer DID creation", func(t *testing.T) {
		prov := mockProvider(t)

		peerVDR, err := peer.New(prov.StorageProviderValue)
		require.NoError(t, err)

		prov.VDRegistryValue = vdr.New(vdr.WithVDR(peerVDR))
		prov.SecretLockValue = &noop.NoLock{}

		prov.KMSValue, err = localkms.New("foo://bar", prov)
		require.NoError(t, err)

		connStore, err := connection.NewRecorder(prov)
		require.NoError(t, err)

		require.NoError(t, connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			MyDID:        myDID,
			TheirDID:     theirDID,
			State:        connection.StateNameCompleted,
		}))

		cmd, err := New(prov)
		require.NoError(t, err)

		req := RotateDIDRequest{
			ID:            connID,
			KID:           myDID + "#key-2",
			CreatePeerDID: true,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		cmdErr := cmd.RotateDID(rw, bytes.NewReader(reqBytes))
		require.NoError(t, cmdErr)

		resp := RotateDIDResponse{}

		err = json.NewDecoder(rw.Result().Body).Decode(&resp)
		require.NoError(t, err)

		parsed, err := did.Parse(resp.NewDID)
		require.NoError(t, err)
		require.Equal(t, "peer", parsed.Method)
	})

	t.Run("fail: parse request", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		cmdErr := cmd.RotateDID(nil, bytes.NewReader([]byte("bad message")))
		require.Error(t, cmdErr)
	})

	t.Run("fail: missing connection ID", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := RotateDIDRequest{
			KID:    myDID + "#key-2",
			NewDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		cmdErr := cmd.RotateDID(nil, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyConnID)
	})

	t.Run("fail: missing key ID", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := RotateDIDRequest{
			ID:     connID,
			NewDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		cmdErr := cmd.RotateDID(nil, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyKID)
	})

	t.Run("fail: missing new DID", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := RotateDIDRequest{
			ID:  connID,
			KID: myDID + "#key-2",
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		cmdErr := cmd.RotateDID(nil, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyNewDID)
	})

	t.Run("fail: error in client execution", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		req := RotateDIDRequest{
			ID:     connID,
			KID:    myDID + "#key-2",
			NewDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		cmdErr := cmd.RotateDID(nil, bytes.NewReader(reqBytes))
		require.Error(t, cmdErr)
		require.Equal(t, RotateDIDErrorCode, cmdErr.Code())
	})
}

func TestCommand_RotateDIDGivenConnIDCmd(t *testing.T) {
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

		cmd, err := New(prov)
		require.NoError(t, err)

		req := RotateDIDRequest{
			ID:     connID,
			KID:    myDID + "#key-2",
			NewDID: theirDID,
		}

		reqBytes, err := json.Marshal(&req)
		require.NoError(t, err)

		rotateCmd := cmd.RotateDIDGivenConnIDCmd(connID)

		rw := httptest.NewRecorder()

		cmdErr := rotateCmd(rw, bytes.NewReader(reqBytes))
		require.NoError(t, cmdErr)

		resp := RotateDIDResponse{}

		err = json.NewDecoder(rw.Result().Body).Decode(&resp)
		require.NoError(t, err)

		require.Equal(t, theirDID, resp.NewDID)
	})

	t.Run("fail: parse request", func(t *testing.T) {
		prov := mockProvider(t)

		cmd, err := New(prov)
		require.NoError(t, err)

		rotateCmd := cmd.RotateDIDGivenConnIDCmd(connID)

		cmdErr := rotateCmd(nil, bytes.NewReader([]byte("bad message")))
		require.Error(t, cmdErr)
	})
}
