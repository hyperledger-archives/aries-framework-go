/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/connectionstore"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	mockdidconnection "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/didconnection"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	threadIDValue = "xyz"
	connIDValue   = "connValue"
)

func Test_ComputeHash(t *testing.T) {
	h1, err := computeHash([]byte("sample-bytes-123"))
	require.NoError(t, err)
	require.NotEmpty(t, h1)

	h2, err := computeHash([]byte("sample-bytes-321"))
	require.NoError(t, err)
	require.NotEmpty(t, h2)

	h3, err := computeHash([]byte("sample-bytes-123"))
	require.NoError(t, err)
	require.NotEmpty(t, h1)

	require.NotEqual(t, h1, h2)
	require.Equal(t, h1, h3)

	h4, err := computeHash([]byte(""))
	require.Error(t, err)
	require.Empty(t, h4)
}

func TestNewConnectionStore(t *testing.T) {
	t.Run("test create connection store", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, record)
	})
	t.Run("test create connection store - error", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{
			StoreProvider: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("sample-error"),
			},
		})
		require.Error(t, err)
		require.Nil(t, record)
	})
}

func TestConnectionStore_SaveInvitation(t *testing.T) {
	t.Run("test save invitation success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record, err := newConnectionStore(&protocol.MockProvider{
			StoreProvider: mockstorage.NewCustomMockStoreProvider(store),
		})
		require.NoError(t, err)

		require.NotNil(t, record)

		value := &Invitation{
			Header: service.Header{
				ID: "sample-id1",
			},
			Label: "sample-label1",
		}

		err = record.SaveInvitation(value)
		require.NoError(t, err)

		require.NotEmpty(t, store)

		k, err := invitationKey(value.ID)
		require.NoError(t, err)
		require.NotEmpty(t, k)

		v, err := record.Store().Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)
	})

	t.Run("test save invitation failure due to invalid key", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record, err := newConnectionStore(&protocol.MockProvider{
			StoreProvider: mockstorage.NewCustomMockStoreProvider(store),
		})
		require.NoError(t, err)
		require.NotNil(t, record)

		value := &Invitation{
			Label: "sample-label2",
		}
		err = record.SaveInvitation(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty bytes")
	})
}

func TestConnectionStore_GetInvitation(t *testing.T) {
	t.Run("test get invitation - success", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, record)

		valueStored := &Invitation{
			Header: service.Header{
				ID: "sample-id-3",
			},
			Label: "sample-label-3",
		}

		err = record.SaveInvitation(valueStored)
		require.NoError(t, err)

		valueFound, err := record.GetInvitation(valueStored.ID)
		require.NoError(t, err)
		require.Equal(t, valueStored, valueFound)
	})

	t.Run("test get invitation - not found scenario", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, record)

		valueFound, err := record.GetInvitation("sample-key4")
		require.Error(t, err)
		require.Equal(t, err, storage.ErrDataNotFound)
		require.Nil(t, valueFound)
	})

	t.Run("test get invitation - invalid key scenario", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, record)

		valueFound, err := record.GetInvitation("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty bytes")
		require.Nil(t, valueFound)
	})
}

func TestConnectionRecordByState(t *testing.T) {
	record, err := newConnectionStore(&protocol.MockProvider{})
	require.NoError(t, err)

	connRec := &connectionstore.ConnectionRecord{ConnectionID: generateRandomID(), ThreadID: threadIDValue,
		Namespace: myNSPrefix, State: "requested"}
	err = record.saveConnectionRecord(connRec)
	require.NoError(t, err)

	// data exists
	storedConnRec, err := record.GetConnectionRecordAtState(connRec.ConnectionID, "requested")
	require.NoError(t, err)
	require.Equal(t, storedConnRec, connRec)

	// data doesn't exists
	_, err = record.GetConnectionRecordAtState(connRec.ConnectionID, "invalid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "data not found")

	// data with no state details
	connRec = &connectionstore.ConnectionRecord{ConnectionID: generateRandomID(), ThreadID: threadIDValue,
		Namespace: myNSPrefix}
	err = record.saveConnectionRecord(connRec)
	require.NoError(t, err)
	_, err = record.GetConnectionRecordAtState(connRec.ConnectionID, "requested")
	require.Error(t, err)
	require.Contains(t, err.Error(), "data not found")

	// get with empty stateID
	_, err = record.GetConnectionRecordAtState(connRec.ConnectionID, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "stateID can't be empty")
}

func TestConnectionRecorder_SaveConnectionRecord(t *testing.T) {
	t.Run("save connection record and get connection Record success", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		connRec := &connectionstore.ConnectionRecord{ThreadID: threadIDValue,

			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err = record.saveNewConnectionRecord(connRec)
		require.NoError(t, err)

		storedRecord, err := record.GetConnectionRecord(connRec.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run("save connection record and fetch from no namespace error", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		connRec := &connectionstore.ConnectionRecord{ThreadID: threadIDValue,

			ConnectionID: connIDValue, State: stateNameInvited}
		err = record.saveNewConnectionRecord(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty")
	})
	t.Run("save connection record error", func(t *testing.T) {
		const errMsg = "get error"
		record, err := newConnectionStore(&protocol.MockProvider{
			TransientStoreProvider: mockstorage.NewCustomMockStoreProvider(&mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf(errMsg),
			}),
		})
		require.NoError(t, err)
		connRec := &connectionstore.ConnectionRecord{ThreadID: "",
			ConnectionID: "test", State: stateNameInvited, Namespace: theirNSPrefix}
		err = record.saveConnectionRecord(connRec)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("save connection record error", func(t *testing.T) {
		const errMsg = "get error"
		record, err := newConnectionStore(&protocol.MockProvider{
			TransientStoreProvider: mockstorage.NewCustomMockStoreProvider(&mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf(errMsg),
			}),
		})
		require.NoError(t, err)
		connRec := &connectionstore.ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err = record.saveNewConnectionRecord(connRec)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("save connection record in permanent store error", func(t *testing.T) {
		const errMsg = "get error"
		record, err := newConnectionStore(&protocol.MockProvider{
			StoreProvider: mockstorage.NewCustomMockStoreProvider(&mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf(errMsg),
			}),
		})
		require.NoError(t, err)

		require.NotNil(t, record)
		connRec := &connectionstore.ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameCompleted, Namespace: theirNSPrefix}
		err = record.saveNewConnectionRecord(connRec)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("error saving DID by resolving", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{
			DIDConnectionStoreValue: &mockdidconnection.MockDIDConnection{
				ResolveDIDErr: fmt.Errorf("save error"),
			},
		})
		require.NotNil(t, record)
		require.NoError(t, err)

		connRec := &connectionstore.ConnectionRecord{ThreadID: threadIDValue, MyDID: "did:foo",
			ConnectionID: connIDValue, State: stateNameCompleted, Namespace: theirNSPrefix}
		err = record.saveNewConnectionRecord(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "save error")

		// note: record is still stored, since error happens afterwards
		storedRecord, err := record.GetConnectionRecord(connRec.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
}

func TestConnectionRecorder_GetConnectionRecordByNSThreadID(t *testing.T) {
	t.Run(" get connection record by namespace threadID in my namespace", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)

		require.NotNil(t, record)
		connRec := &connectionstore.ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: myNSPrefix}
		err = record.saveNewConnectionRecord(connRec)
		require.NoError(t, err)

		nsThreadID, err := createNSKey(myNSPrefix, threadIDValue)
		require.NoError(t, err)

		storedRecord, err := record.GetConnectionRecordByNSThreadID(nsThreadID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run(" get connection record by namespace threadID their namespace", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, record)
		connRec := &connectionstore.ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err = record.saveNewConnectionRecord(connRec)
		require.NoError(t, err)

		nsThreadID, err := createNSKey(theirNSPrefix, threadIDValue)
		require.NoError(t, err)

		storedRecord, err := record.GetConnectionRecordByNSThreadID(nsThreadID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run(" data not found error due to missing input parameter", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, record)
		connRec, err := record.GetConnectionRecordByNSThreadID("")
		require.Contains(t, err.Error(), "data not found")
		require.Nil(t, connRec)
	})
}

func TestConnectionRecorder_CreateNSKeys(t *testing.T) {
	t.Run(" creating their namespace key success", func(t *testing.T) {
		key, err := createNSKey(theirNSPrefix, threadIDValue)
		require.NoError(t, err)
		require.NotNil(t, key)
	})
	t.Run(" check error while creating my namespace key", func(t *testing.T) {
		_, err := createNSKey(myNSPrefix, "")
		require.Contains(t, err.Error(), "empty bytes")
	})
}

func TestConnectionRecorder_SaveNSThreadID(t *testing.T) {
	t.Run("missing required parameters", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)

		require.NotNil(t, record)
		err = record.saveNSThreadID("", theirNSPrefix, connIDValue)
		require.Error(t, err)
		err = record.saveNSThreadID("", myNSPrefix, connIDValue)
		require.Error(t, err)
		err = record.saveNSThreadID(threadIDValue, "", connIDValue)
		require.Error(t, err)
	})
}
