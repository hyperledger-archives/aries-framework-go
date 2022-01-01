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
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	threadIDValue    = "xyz"
	sampleConnID     = "sample-conn-ID"
	stateNameInvited = "invited"
)

func Test_NewConnectionRecorder(t *testing.T) {
	t.Run("create create new recorder - success", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)
	})

	t.Run("create new connection recorder - protocol state store error", func(t *testing.T) {
		lookup, err := NewRecorder(&mockProvider{protocolStateStoreError: fmt.Errorf(sampleErrMsg)})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErrMsg)
		require.Nil(t, lookup)
	})

	t.Run("create new connection recorder - permanent store error", func(t *testing.T) {
		lookup, err := NewRecorder(&mockProvider{storeError: fmt.Errorf(sampleErrMsg)})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErrMsg)
		require.Nil(t, lookup)
	})
}

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

func Test_RemoveMappings(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID: threadIDValue,
		}

		err = removeMappings(recorder, record)
		require.NoError(t, err)
	})
	t.Run("test failed - empty bytes", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID: "",
		}

		err = removeMappings(recorder, record)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty bytes")
	})
	t.Run("test failed to delete the record", func(t *testing.T) {
		const errMsg = "get error"
		recorder, err := NewRecorder(&mockProvider{
			store: &mockstorage.MockStore{
				Store:     make(map[string]mockstorage.DBEntry),
				ErrDelete: fmt.Errorf(errMsg),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID: threadIDValue,
		}

		err = removeMappings(recorder, record)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
}

func Test_RemoveConnectionRecordsForStates(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		record := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: uuid.New().String(),
			State:        StateNameCompleted,
			Namespace:    TheirNSPrefix,
			MyDID:        "did:mydid:123",
			TheirDID:     "did:theirdid:123",
		}

		store := &mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry),
		}

		err := marshalAndSave(getConnectionStateKeyPrefix()(record.ConnectionID, record.State),
			record, store)
		require.NoError(t, err)

		recorder, err := NewRecorder(&mockProvider{
			protocolStateStore: store,
		})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		err = removeConnectionsForStates(recorder, record.ConnectionID)
		require.NoError(t, err)
	})
	t.Run("test failed to delete connection state record from the store", func(t *testing.T) {
		const errMsg = "get error"
		record := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: uuid.New().String(),
			State:        StateNameCompleted,
			Namespace:    TheirNSPrefix,
			MyDID:        "did:mydid:123",
			TheirDID:     "did:theirdid:123",
		}

		store := &mockstorage.MockStore{
			Store:     make(map[string]mockstorage.DBEntry),
			ErrDelete: fmt.Errorf(errMsg),
		}

		err := marshalAndSave(getConnectionStateKeyPrefix()(record.ConnectionID, record.State),
			record, store, storage.Tag{
				Name:  connStateKeyPrefix,
				Value: getConnectionStateKeyPrefix()(record.ConnectionID),
			})
		require.NoError(t, err)

		recorder, err := NewRecorder(&mockProvider{
			protocolStateStore: store,
		})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		err = removeConnectionsForStates(recorder, record.ConnectionID)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestConnectionStore_SaveInvitation(t *testing.T) {
	const id = "sample-inv-id"

	t.Run("test save invitation success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}
		recorder, err := NewRecorder(&mockProvider{
			store: store,
		})
		require.NoError(t, err)

		require.NotNil(t, recorder)

		value := &mockInvitation{
			ID:    id,
			Label: "sample-label1",
		}

		err = recorder.SaveInvitation(value.ID, value)
		require.NoError(t, err)

		require.NotEmpty(t, store)

		k := getInvitationKeyPrefix()(value.ID)

		v, err := recorder.Lookup.store.Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)

		var v1 mockInvitation
		err = getAndUnmarshal(k, &v1, recorder.store)
		require.NoError(t, err)
		require.Equal(t, value, &v1)

		var v2 mockInvitation
		err = getAndUnmarshal(k, &v2, recorder.protocolStateStore)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
	})

	t.Run("test save invitation failure due to invalid key", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}
		recorder, err := NewRecorder(&mockProvider{
			store: store,
		})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		value := &mockInvitation{
			Label: "sample-label2",
		}
		err = recorder.SaveInvitation("", value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key")
	})
}

func TestConnectionStore_GetInvitation(t *testing.T) {
	t.Run("test get invitation - success", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		valueStored := &mockInvitation{
			ID:    "sample-id-3",
			Label: "sample-label-3",
		}

		err = recorder.SaveInvitation(valueStored.ID, valueStored)
		require.NoError(t, err)

		var valueFound mockInvitation
		err = recorder.GetInvitation(valueStored.ID, &valueFound)
		require.NoError(t, err)
		require.Equal(t, valueStored, &valueFound)
	})

	t.Run("test get invitation - not found scenario", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		var valueFound mockInvitation
		err = recorder.GetInvitation("sample-key4", &valueFound)
		require.Error(t, err)
		require.Equal(t, err, storage.ErrDataNotFound)
	})

	t.Run("test get invitation - invalid key scenario", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		var valueFound mockInvitation
		err = recorder.GetInvitation("", &valueFound)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsgInvalidKey)
	})
}

func TestConnectionStore_SaveAndGetOOBv2Invitation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		mockDID := "did:test:abc:def"

		valueStored := &mockInvitation{
			ID:    "sample-id-3",
			Label: "sample-label-3",
		}

		err = recorder.SaveOOBv2Invitation(mockDID, valueStored)
		require.NoError(t, err)

		var valueFound mockInvitation
		err = recorder.GetOOBv2Invitation(mockDID, &valueFound)
		require.NoError(t, err)
		require.Equal(t, valueStored, &valueFound)
	})

	t.Run("fail: lookup without key", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		err = recorder.GetOOBv2Invitation("", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsgInvalidKey)
	})
}

func TestConnectionStore_SaveAndGetEventData(t *testing.T) {
	t.Run("test save and get event data - success", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		valueStored := []byte("sample-event-data")

		err = recorder.SaveEvent(sampleConnID, valueStored)
		require.NoError(t, err)

		valueFound, err := recorder.GetEvent(sampleConnID)
		require.NoError(t, err)
		require.Equal(t, valueStored, valueFound)
	})

	t.Run("test get invitation - not found scenario", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		value, err := recorder.GetEvent(sampleConnID)
		require.Error(t, err)
		require.Equal(t, err, storage.ErrDataNotFound)
		require.Nil(t, value)
	})

	t.Run("test get invitation - invalid key scenario", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		value, err := recorder.GetEvent("")
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsgInvalidKey)
		require.Nil(t, value)
	})
}

func TestConnectionRecordByState(t *testing.T) {
	recorder, err := NewRecorder(&mockProvider{})
	require.NoError(t, err)

	connRec := &Record{
		ConnectionID: uuid.New().String(), ThreadID: threadIDValue,
		Namespace: MyNSPrefix, State: "requested",
	}
	err = recorder.SaveConnectionRecord(connRec)
	require.NoError(t, err)

	// data exists
	storedConnRec, err := recorder.GetConnectionRecordAtState(connRec.ConnectionID, "requested")
	require.NoError(t, err)
	require.Equal(t, storedConnRec, connRec)

	// data doesn't exists
	_, err = recorder.GetConnectionRecordAtState(connRec.ConnectionID, "invalid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "data not found")

	// data with no state details
	connRec = &Record{
		ConnectionID: uuid.New().String(), ThreadID: threadIDValue,
		Namespace: MyNSPrefix,
	}
	err = recorder.SaveConnectionRecord(connRec)
	require.NoError(t, err)
	_, err = recorder.GetConnectionRecordAtState(connRec.ConnectionID, "requested")
	require.Error(t, err)
	require.Contains(t, err.Error(), "data not found")

	// get with empty stateID
	_, err = recorder.GetConnectionRecordAtState(connRec.ConnectionID, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "stateID can't be empty")
}

func TestConnectionRecorder_SaveConnectionRecord(t *testing.T) {
	t.Run("save connection record with invited state - success", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: uuid.New().String(), State: stateNameInvited, Namespace: TheirNSPrefix,
		}
		err = recorder.SaveConnectionRecord(record)
		require.NoError(t, err)

		recordFound, err := recorder.GetConnectionRecord(record.ConnectionID)
		require.NoError(t, err)
		require.NotNil(t, recordFound)
		require.Equal(t, record, recordFound)

		// make sure it exists only in protocol state store
		var r1 Record
		err = getAndUnmarshal(getConnectionKeyPrefix()(record.ConnectionID), &r1, recorder.store)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")

		var r2 Record
		err = getAndUnmarshal(getConnectionKeyPrefix()(record.ConnectionID), &r2, recorder.protocolStateStore)
		require.NoError(t, err)
		require.Equal(t, record, &r2)
	})

	t.Run("save connection record with invited state - completed", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: uuid.New().String(),
			State:        StateNameCompleted,
			Namespace:    TheirNSPrefix,
			MyDID:        "did:mydid:123",
			TheirDID:     "did:theirdid:123",
		}
		err = recorder.SaveConnectionRecord(record)
		require.NoError(t, err)

		recordFound, err := recorder.GetConnectionRecord(record.ConnectionID)
		require.NoError(t, err)
		require.NotNil(t, recordFound)
		require.Equal(t, record, recordFound)

		// make sure it exists only in both permanent and protocol state store
		var r1 Record
		err = getAndUnmarshal(getConnectionKeyPrefix()(record.ConnectionID), &r1, recorder.protocolStateStore)
		require.NoError(t, err)
		require.Equal(t, record, &r1)

		var r2 Record
		err = getAndUnmarshal(getConnectionKeyPrefix()(record.ConnectionID), &r2, recorder.store)
		require.NoError(t, err)
		require.Equal(t, record, &r2)
	})

	t.Run("save connection record error scenario 1", func(t *testing.T) {
		const errMsg = "get error"
		record, err := NewRecorder(&mockProvider{
			protocolStateStore: &mockstorage.MockStore{
				Store:  make(map[string]mockstorage.DBEntry),
				ErrPut: fmt.Errorf(errMsg),
			},
		})
		require.NoError(t, err)
		connRec := &Record{
			ThreadID:     "",
			ConnectionID: "test", State: stateNameInvited, Namespace: TheirNSPrefix,
		}
		err = record.SaveConnectionRecord(connRec)
		require.Contains(t, err.Error(), errMsg)
	})

	t.Run("save connection record error scenario 2", func(t *testing.T) {
		const errMsg = "get error"
		record, err := NewRecorder(&mockProvider{
			store: &mockstorage.MockStore{
				Store:  make(map[string]mockstorage.DBEntry),
				ErrPut: fmt.Errorf(errMsg),
			},
		})
		require.NoError(t, err)
		connRec := &Record{
			ThreadID:     "",
			ConnectionID: "test", State: StateNameCompleted, Namespace: TheirNSPrefix,
		}
		err = record.SaveConnectionRecord(connRec)
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestConnectionRecorder_RemoveConnection(t *testing.T) {
	t.Run("save and remove connection record with invited state - completed", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: uuid.New().String(),
			State:        StateNameCompleted,
			Namespace:    TheirNSPrefix,
			MyDID:        "did:mydid:123",
			TheirDID:     "did:theirdid:123",
		}
		err = recorder.SaveConnectionRecord(record)
		require.NoError(t, err)

		recordFound, err := recorder.GetConnectionRecord(record.ConnectionID)
		require.NoError(t, err)
		require.NotNil(t, recordFound)
		require.Equal(t, record, recordFound)

		err = recorder.RemoveConnection(record.ConnectionID)
		require.NoError(t, err)

		// make sure no records exist in both permanent and protocol state store
		var r1 Record
		err = getAndUnmarshal(getConnectionKeyPrefix()(record.ConnectionID), &r1, recorder.protocolStateStore)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")

		var r2 Record
		err = getAndUnmarshal(getConnectionKeyPrefix()(record.ConnectionID), &r2, recorder.store)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")

		itr, err := recorder.protocolStateStore.Query(connStateKeyPrefix)
		require.NoError(t, err)

		hasRecords, err := itr.Next()
		require.NoError(t, err)

		if hasRecords {
			key, errKey := itr.Key()
			require.NoError(t, errKey)

			t.Errorf("protocol state store still has connection state records: key=%s", key)
		}

		_, err = recorder.GetConnectionRecordByDIDs(record.MyDID, record.TheirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
	})
	t.Run("try to remove unexisting connection record", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: uuid.New().String(),
			State:        StateNameCompleted,
			Namespace:    TheirNSPrefix,
			MyDID:        "did:mydid:123",
			TheirDID:     "did:theirdid:123",
		}

		err = recorder.RemoveConnection(record.ConnectionID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
	})
	t.Run("save and remove connection record - failed to delete from the store", func(t *testing.T) {
		const errMsg = "get error"
		recorder, err := NewRecorder(&mockProvider{
			store: &mockstorage.MockStore{
				Store:     make(map[string]mockstorage.DBEntry),
				ErrDelete: fmt.Errorf(errMsg),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: uuid.New().String(),
			State:        StateNameCompleted,
			Namespace:    TheirNSPrefix,
			MyDID:        "did:mydid:123",
			TheirDID:     "did:theirdid:123",
		}
		err = recorder.SaveConnectionRecord(record)
		require.NoError(t, err)

		err = recorder.RemoveConnection(record.ConnectionID)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("save and remove connection record - failed to delete from the protocol state store", func(t *testing.T) {
		const errMsg = "get error"
		recorder, err := NewRecorder(&mockProvider{
			protocolStateStore: &mockstorage.MockStore{
				Store:     make(map[string]mockstorage.DBEntry),
				ErrDelete: fmt.Errorf(errMsg),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: uuid.New().String(),
			State:        StateNameCompleted,
			Namespace:    TheirNSPrefix,
			MyDID:        "did:mydid:123",
			TheirDID:     "did:theirdid:123",
		}
		err = recorder.SaveConnectionRecord(record)
		require.NoError(t, err)

		err = recorder.RemoveConnection(record.ConnectionID)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("save and remove connection record - failed to delete connection mapping record", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)

		record := &Record{
			ThreadID:     "",
			ConnectionID: uuid.New().String(),
			State:        StateNameCompleted,
			Namespace:    TheirNSPrefix,
			MyDID:        "did:mydid:123",
			TheirDID:     "did:theirdid:123",
		}
		err = recorder.SaveConnectionRecord(record)
		require.NoError(t, err)

		err = recorder.RemoveConnection(record.ConnectionID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty bytes")
	})
}

func TestConnectionRecorder_ConnectionRecordMappings(t *testing.T) {
	t.Run("get connection record by namespace threadID in my namespace", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)

		require.NotNil(t, recorder)
		connRec := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: sampleConnID, State: stateNameInvited, Namespace: MyNSPrefix,
		}
		err = recorder.SaveConnectionRecordWithMappings(connRec)
		require.NoError(t, err)

		nsThreadID, err := CreateNamespaceKey(MyNSPrefix, threadIDValue)
		require.NoError(t, err)

		storedRecord, err := recorder.GetConnectionRecordByNSThreadID(nsThreadID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run("get connection record by namespace threadID their namespace", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)
		connRec := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: sampleConnID, State: stateNameInvited, Namespace: TheirNSPrefix,
		}
		err = recorder.SaveConnectionRecordWithMappings(connRec)
		require.NoError(t, err)

		nsThreadID, err := CreateNamespaceKey(TheirNSPrefix, threadIDValue)
		require.NoError(t, err)

		storedRecord, err := recorder.GetConnectionRecordByNSThreadID(nsThreadID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run("save connection record with mapping - validation failure", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)

		require.NotNil(t, recorder)
		connRec := &Record{
			ThreadID:     "",
			ConnectionID: sampleConnID, State: stateNameInvited, Namespace: MyNSPrefix,
		}
		err = recorder.SaveConnectionRecordWithMappings(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "validation failed")
	})
	t.Run("save connection record with mapping - store failure", func(t *testing.T) {
		const errMsg = "put error"
		recorder, err := NewRecorder(&mockProvider{
			protocolStateStore: &mockstorage.MockStore{
				Store:  make(map[string]mockstorage.DBEntry),
				ErrPut: fmt.Errorf(errMsg),
			},
		})

		require.NotNil(t, recorder)
		require.NoError(t, err)

		connRec := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: sampleConnID, State: stateNameInvited, Namespace: MyNSPrefix,
		}
		err = recorder.SaveConnectionRecordWithMappings(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("save connection record with mapping - namespace error", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)

		require.NotNil(t, recorder)
		connRec := &Record{
			ThreadID:     threadIDValue,
			ConnectionID: sampleConnID, State: stateNameInvited, Namespace: "invalid-ns",
		}
		err = recorder.SaveConnectionRecordWithMappings(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "namespace not supported")
	})
	t.Run("data not found error due to missing input parameter", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)
		require.NotNil(t, recorder)
		connRec, err := recorder.GetConnectionRecordByNSThreadID("")
		require.Contains(t, err.Error(), "data not found")
		require.Nil(t, connRec)
	})
}

func TestConnectionRecorder_CreateNSKeys(t *testing.T) {
	t.Run("creating their namespace key success", func(t *testing.T) {
		key, err := CreateNamespaceKey(TheirNSPrefix, threadIDValue)
		require.NoError(t, err)
		require.NotNil(t, key)
	})
	t.Run("check error while creating my namespace key", func(t *testing.T) {
		_, err := CreateNamespaceKey(MyNSPrefix, "")
		require.Contains(t, err.Error(), "empty bytes")
	})
}

func TestConnectionRecorder_SaveNamespaceThreadID(t *testing.T) {
	t.Run("missing required parameters", func(t *testing.T) {
		recorder, err := NewRecorder(&mockProvider{})
		require.NoError(t, err)

		require.NotNil(t, recorder)
		err = recorder.SaveNamespaceThreadID("", TheirNSPrefix, sampleConnID)
		require.Error(t, err)
		err = recorder.SaveNamespaceThreadID("", MyNSPrefix, sampleConnID)
		require.Error(t, err)
		err = recorder.SaveNamespaceThreadID(threadIDValue, "", sampleConnID)
		require.Error(t, err)
	})
}

func TestConnectionRecorder_SaveAndGet(t *testing.T) {
	const noOfRecords = 12

	records := make([]*mockInvitation, noOfRecords)
	for i := 0; i < noOfRecords; i++ {
		records[i] = &mockInvitation{ID: fmt.Sprintf("conn-%d", i)}
	}

	t.Run("save and get in store - success", func(t *testing.T) {
		require.NotEmpty(t, records)
		store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}

		for _, record := range records {
			err := marshalAndSave(record.ID, record, store)
			require.NoError(t, err)
		}

		for _, record := range records {
			var recordFound1 mockInvitation
			err := getAndUnmarshal(record.ID, &recordFound1, store)
			require.NoError(t, err)
			require.Equal(t, record, &recordFound1)
		}
	})

	t.Run("save and get in store - store failure", func(t *testing.T) {
		const errMsg = "put error"

		store := &mockstorage.MockStore{
			Store:  make(map[string]mockstorage.DBEntry),
			ErrPut: fmt.Errorf(errMsg),
			ErrGet: fmt.Errorf(errMsg),
		}

		require.NotEmpty(t, records)

		for _, record := range records {
			err := marshalAndSave(record.ID, record, store)
			require.Error(t, err)
			require.Contains(t, err.Error(), errMsg)
		}

		for _, record := range records {
			var recordFound1 mockInvitation
			err := getAndUnmarshal(record.ID, &recordFound1, store)
			require.Error(t, err)
			require.Contains(t, err.Error(), errMsg)
		}
	})

	t.Run("save and get in store - failure", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}

		err := marshalAndSave("sample-id", make(chan int), store)
		require.Error(t, err)

		err = marshalAndSave("sample-id", []byte("XYZ"), store)
		require.NoError(t, err)

		err = getAndUnmarshal("sample-id", make(chan int), store)
		require.Error(t, err)
	})
}

type mockInvitation struct {
	ImageURL        string            `json:"imageUrl,omitempty"`
	ServiceEndpoint string            `json:"serviceEndpoint,omitempty"`
	RecipientKeys   []string          `json:"recipientKeys,omitempty"`
	ID              string            `json:"@id,omitempty"`
	Label           string            `json:"label,omitempty"`
	DID             string            `json:"did,omitempty"`
	RoutingKeys     []string          `json:"routingKeys,omitempty"`
	Type            string            `json:"@type,omitempty"`
	Thread          *decorator.Thread `json:"~thread,omitempty"`
}
