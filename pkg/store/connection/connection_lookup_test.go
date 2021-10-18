/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package connection

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	threadIDFmt  = "thID-%v"
	connIDFmt    = "connValue-%v"
	sampleErrMsg = "sample-error-message"
)

func TestNewConnectionReader(t *testing.T) {
	t.Run("create new connection reader", func(t *testing.T) {
		lookup, err := NewLookup(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, lookup)
		require.NotNil(t, lookup.protocolStateStore)
		require.NotNil(t, lookup.store)
	})

	t.Run("create new connection reader failure due to protocol state store error", func(t *testing.T) {
		lookup, err := NewLookup(&mockProvider{protocolStateStoreError: fmt.Errorf(sampleErrMsg)})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErrMsg)
		require.Nil(t, lookup)
	})

	t.Run("create new connection reader failure due to protocol state store config error", func(t *testing.T) {
		lookup, err := NewLookup(&mockProvider{protocolStoreConfError: fmt.Errorf(sampleErrMsg)})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErrMsg)
		require.Nil(t, lookup)
	})

	t.Run("create new connection reader failure due to store error", func(t *testing.T) {
		lookup, err := NewLookup(&mockProvider{storeError: fmt.Errorf(sampleErrMsg)})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErrMsg)
		require.Nil(t, lookup)
	})

	t.Run("create new connection reader failure due to store config error", func(t *testing.T) {
		lookup, err := NewLookup(&mockProvider{storeConfError: fmt.Errorf(sampleErrMsg)})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErrMsg)
		require.Nil(t, lookup)
	})
}

func TestConnectionReader_GetAndQueryConnectionRecord(t *testing.T) {
	const noOfItems = 12
	connectionIDS := make([]string, noOfItems)

	for i := 0; i < noOfItems; i++ {
		connectionIDS[i] = fmt.Sprintf(connIDFmt, i)
	}

	saveInStore := func(store storage.Store, ids []string) {
		for _, id := range ids {
			connRecBytes, err := json.Marshal(&Record{
				ConnectionID: id,
				ThreadID:     fmt.Sprintf(threadIDFmt, id),
			})
			require.NoError(t, err)
			err = store.Put(getConnectionKeyPrefix()(id), connRecBytes, storage.Tag{Name: "conn_"})
			require.NoError(t, err)
		}
	}

	t.Run("get connection record - from store", func(t *testing.T) {
		lookup, e := NewLookup(&mockProvider{})
		require.NoError(t, e)
		require.NotNil(t, lookup)

		for _, connectionID := range connectionIDS {
			connection, err := lookup.GetConnectionRecord(connectionID)
			require.Error(t, err)
			require.Equal(t, err, storage.ErrDataNotFound)
			require.Nil(t, connection)
		}

		// prepare data
		saveInStore(lookup.store, connectionIDS)

		for _, connectionID := range connectionIDS {
			connection, err := lookup.GetConnectionRecord(connectionID)
			require.NoError(t, err)
			require.NotNil(t, connection)
			require.Equal(t, connectionID, connection.ConnectionID)
			require.Equal(t, fmt.Sprintf(threadIDFmt, connectionID), connection.ThreadID)
		}

		records, e := lookup.QueryConnectionRecords()
		require.NoError(t, e)
		require.NotEmpty(t, records)
		require.Len(t, records, noOfItems)
	})

	t.Run("get connection record - from protocol state store", func(t *testing.T) {
		lookup, e := NewLookup(&mockProvider{})
		require.NoError(t, e)
		require.NotNil(t, lookup)

		for _, connectionID := range connectionIDS {
			connection, err := lookup.GetConnectionRecord(connectionID)
			require.Error(t, err)
			require.Equal(t, err, storage.ErrDataNotFound)
			require.Nil(t, connection)
		}

		// prepare data
		saveInStore(lookup.protocolStateStore, connectionIDS)

		for _, connectionID := range connectionIDS {
			connection, err := lookup.GetConnectionRecord(connectionID)
			require.NoError(t, err)
			require.NotNil(t, connection)
			require.Equal(t, connectionID, connection.ConnectionID)
			require.Equal(t, fmt.Sprintf(threadIDFmt, connectionID), connection.ThreadID)
		}

		records, e := lookup.QueryConnectionRecords()
		require.NoError(t, e)
		require.NotEmpty(t, records)
		require.Len(t, records, noOfItems)
	})

	t.Run("get connection record - error scenario", func(t *testing.T) {
		provider := &mockProvider{}
		provider.store = &mockstorage.MockStore{
			ErrGet: fmt.Errorf(sampleErrMsg),
			Store:  make(map[string]mockstorage.DBEntry),
		}
		lookup, err := NewLookup(provider)
		require.NoError(t, err)
		require.NotNil(t, lookup)

		// prepare data
		saveInStore(lookup.protocolStateStore, connectionIDS)

		for _, connectionID := range connectionIDS {
			connection, err := lookup.GetConnectionRecord(connectionID)
			require.Error(t, err)
			require.Nil(t, connection)
			require.EqualError(t, err, sampleErrMsg)
		}
	})
}

func TestConnectionReader_GetConnectionRecordAtState(t *testing.T) {
	const state = "requested"

	const noOfItems = 12

	connectionIDS := make([]string, noOfItems)

	for i := 0; i < noOfItems; i++ {
		connectionIDS[i] = fmt.Sprintf(connIDFmt, i)
	}

	saveInStore := func(store storage.Store, ids []string) {
		for _, id := range ids {
			connRecBytes, err := json.Marshal(&Record{
				ConnectionID: id,
				ThreadID:     fmt.Sprintf(threadIDFmt, id),
			})
			require.NoError(t, err)
			err = store.Put(getConnectionStateKeyPrefix()(id, state), connRecBytes)
			require.NoError(t, err)
		}
	}

	t.Run("get connection record at state", func(t *testing.T) {
		store, err := NewLookup(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, store)

		// should fail since data doesn't exists
		for _, connectionID := range connectionIDS {
			connection, err := store.GetConnectionRecordAtState(connectionID, state)
			require.Error(t, err)
			require.Contains(t, err.Error(), storage.ErrDataNotFound.Error())
			require.Nil(t, connection)
		}

		// prepare data in store
		saveInStore(store.store, connectionIDS)

		// should fail since data doesn't exists in protocol state store
		for _, connectionID := range connectionIDS {
			connection, err := store.GetConnectionRecordAtState(connectionID, state)
			require.Error(t, err)
			require.Contains(t, err.Error(), storage.ErrDataNotFound.Error())
			require.Nil(t, connection)
		}

		// prepare data in protocol state store
		saveInStore(store.protocolStateStore, connectionIDS)

		for _, connectionID := range connectionIDS {
			connection, err := store.GetConnectionRecordAtState(connectionID, state)
			require.NoError(t, err)
			require.NotNil(t, connection)
			require.Equal(t, connectionID, connection.ConnectionID)
			require.Equal(t, fmt.Sprintf(threadIDFmt, connectionID), connection.ThreadID)
		}
	})

	t.Run("get connection record at state - failure", func(t *testing.T) {
		store, err := NewLookup(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, store)

		connection, err := store.GetConnectionRecordAtState("sampleID", "")
		require.Error(t, err)
		require.EqualError(t, err, stateIDEmptyErr)
		require.Nil(t, connection)
	})
}

func TestConnectionReader_GetConnectionRecordByNSThreadID(t *testing.T) {
	const noOfItems = 12
	nsThreadIDs := make([]string, noOfItems)

	for i := 0; i < noOfItems; i++ {
		nsThreadIDs[i] = fmt.Sprintf(threadIDFmt, i)
	}

	saveInStore := func(store storage.Store, ids []string, skipConnection bool) {
		for _, id := range ids {
			connID := fmt.Sprintf(connIDFmt, id)
			connRecBytes, err := json.Marshal(&Record{
				ConnectionID: id,
				ThreadID:     id,
			})
			require.NoError(t, err)
			err = store.Put(id, []byte(connID))
			require.NoError(t, err)

			if !skipConnection {
				err = store.Put(getConnectionKeyPrefix()(connID), connRecBytes)
				require.NoError(t, err)
			}
		}
	}

	t.Run("get connection record by NS thread ID", func(t *testing.T) {
		store, err := NewLookup(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, store)

		// should fail since data doesn't exists
		for _, nsThreadID := range nsThreadIDs {
			connection, err := store.GetConnectionRecordByNSThreadID(nsThreadID)
			require.Error(t, err)
			require.Contains(t, err.Error(), storage.ErrDataNotFound.Error())
			require.Nil(t, connection)
		}

		// prepare data in store
		saveInStore(store.store, nsThreadIDs, false)

		// should fail since data doesn't exists in protocol state store
		for _, nsThreadID := range nsThreadIDs {
			connection, err := store.GetConnectionRecordByNSThreadID(nsThreadID)
			require.Error(t, err)
			require.Contains(t, err.Error(), storage.ErrDataNotFound.Error())
			require.Nil(t, connection)
		}

		// prepare only ns thread data in protocol state store
		// skip connection
		saveInStore(store.protocolStateStore, nsThreadIDs, true)

		// should fail since data doesn't exists in protocol state store
		for _, nsThreadID := range nsThreadIDs {
			connection, err := store.GetConnectionRecordByNSThreadID(nsThreadID)
			require.Error(t, err)
			require.Contains(t, err.Error(), storage.ErrDataNotFound.Error())
			require.Nil(t, connection)
		}

		// prepare data in protocol state store
		saveInStore(store.protocolStateStore, nsThreadIDs, false)

		// should fail since data doesn't exists in protocol state store
		for _, nsThreadID := range nsThreadIDs {
			connection, err := store.GetConnectionRecordByNSThreadID(nsThreadID)
			require.NoError(t, err)
			require.NotNil(t, connection)
			require.Equal(t, nsThreadID, connection.ThreadID)
		}
	})
}

func TestConnectionRecorder_QueryConnectionRecord(t *testing.T) {
	t.Run("test query connection record", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}

		protocolStateStore, err := mem.NewProvider().OpenStore(Namespace)
		require.NoError(t, err)

		const (
			storeCount              = 5
			overlap                 = 3
			protocolStateStoreCount = 4
		)

		for i := 0; i < storeCount+overlap; i++ {
			val, jsonErr := json.Marshal(&Record{
				ConnectionID: fmt.Sprint(i),
			})
			require.NoError(t, jsonErr)

			err = store.Put(fmt.Sprintf("%s_abc%d", connIDKeyPrefix, i), val, storage.Tag{Name: "conn_"})
			require.NoError(t, err)
		}
		for i := overlap; i < protocolStateStoreCount+storeCount; i++ {
			val, jsonErr := json.Marshal(&Record{
				ConnectionID: fmt.Sprint(i),
			})
			require.NoError(t, jsonErr)

			err = protocolStateStore.Put(fmt.Sprintf("%s_abc%d", connIDKeyPrefix, i), val, storage.Tag{Name: "conn_"})
			require.NoError(t, err)
		}

		recorder, err := NewLookup(&mockProvider{store: store, protocolStateStore: protocolStateStore})
		require.NoError(t, err)
		require.NotNil(t, recorder)
		result, err := recorder.QueryConnectionRecords()
		require.NoError(t, err)
		require.Len(t, result, storeCount+protocolStateStoreCount)
	})

	t.Run("test query connection record failure", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}
		err := store.Put(fmt.Sprintf("%s_abc123", connIDKeyPrefix), []byte("-----"), storage.Tag{Name: "conn_"})
		require.NoError(t, err)

		recorder, err := NewLookup(&mockProvider{store: store})
		require.NoError(t, err)
		require.NotNil(t, recorder)
		result, err := recorder.QueryConnectionRecords()
		require.Error(t, err)
		require.Empty(t, result)
	})

	t.Run("test query connection record failure - protocol state store read", func(t *testing.T) {
		expected := fmt.Errorf("query error")

		recorder, err := NewRecorder(&mockProvider{
			protocolStateStore: &mockstorage.MockStore{ErrQuery: expected},
		})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		result, err := recorder.QueryConnectionRecords()
		require.Error(t, err)
		require.Empty(t, result)
		require.ErrorIs(t, err, expected)
	})
}

func TestGetConnectionIDByDIDs(t *testing.T) {
	myDID := "did:mydid:123"
	theirDID := "did:theirdid:789"

	t.Run("get connection record by did - success", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)

		require.NotNil(t, recorder)
		connRec := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: sampleConnID,
			State:        StateNameCompleted,
			Namespace:    MyNSPrefix,
			MyDID:        myDID,
			TheirDID:     theirDID,
		}
		err = recorder.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		connectionID, err := recorder.GetConnectionIDByDIDs(myDID, theirDID)
		require.NoError(t, err)
		require.Equal(t, sampleConnID, connectionID)

		connectionRecord, err := recorder.GetConnectionRecordByDIDs(myDID, theirDID)
		require.NoError(t, err)
		require.Equal(t, sampleConnID, connectionRecord.ConnectionID)

		connectionRecord, err = recorder.GetConnectionRecordByTheirDID(theirDID)
		require.NoError(t, err)
		require.Equal(t, sampleConnID, connectionRecord.ConnectionID)
	})

	t.Run("get connection record by did - not found", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)

		connectionID, err := recorder.GetConnectionIDByDIDs(myDID, theirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get connection record by DIDs")
		require.Empty(t, connectionID)

		connectionRecord, err := recorder.GetConnectionRecordByDIDs(myDID, theirDID)
		require.Error(t, err)
		require.ErrorIs(t, err, storage.ErrDataNotFound)
		require.Nil(t, connectionRecord)
	})

	t.Run("get connection record by did - store query error", func(t *testing.T) {
		expected := fmt.Errorf("query error")

		recorder, err := NewRecorder(&mockProvider{
			store: &mockstorage.MockStore{ErrQuery: expected},
		})
		require.NoError(t, err)

		connectionRecord, err := recorder.GetConnectionRecordByDIDs(myDID, theirDID)
		require.Error(t, err)
		require.ErrorIs(t, err, expected)
		require.Nil(t, connectionRecord)
	})
}

// mockProvider for connection recorder.
type mockProvider struct {
	protocolStateStoreError error
	storeError              error
	protocolStoreConfError  error
	storeConfError          error
	store                   storage.Store
	protocolStateStore      storage.Store
}

// ProtocolStateStorageProvider is mock protocol state storage provider for connection recorder.
func (p *mockProvider) ProtocolStateStorageProvider() storage.Provider {
	return mockStorageProvider(p.protocolStateStore, p.protocolStateStoreError, p.protocolStoreConfError)
}

// StorageProvider is mock storage provider for connection recorder.
func (p *mockProvider) StorageProvider() storage.Provider {
	return mockStorageProvider(p.store, p.storeError, p.storeConfError)
}

func mockStorageProvider(store storage.Store, errOpen, errConfig error) storage.Provider {
	if errOpen != nil {
		return &mockstorage.MockStoreProvider{ErrOpenStoreHandle: errOpen}
	}

	var m *mockstorage.MockStoreProvider

	if store != nil {
		m = mockstorage.NewCustomMockStoreProvider(store)
	} else {
		m = mockstorage.NewMockStoreProvider()
	}

	m.ErrSetStoreConfig = errConfig

	return m
}
