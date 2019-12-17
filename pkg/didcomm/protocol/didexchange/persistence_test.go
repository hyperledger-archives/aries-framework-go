/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockdidconnection "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/didconnection"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
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

func TestConnectionRecord_SaveInvitation(t *testing.T) {
	t.Run("test save invitation success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(nil, store, nil)
		require.NotNil(t, record)

		value := &Invitation{
			ID:    "sample-id1",
			Label: "sample-label1",
		}

		err := record.SaveInvitation(value)
		require.NoError(t, err)

		require.NotEmpty(t, store)

		k, err := invitationKey(value.ID)
		require.NoError(t, err)
		require.NotEmpty(t, k)

		v, err := record.store.Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)
	})

	t.Run("test save invitation failure due to invalid key", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(nil, store, nil)
		require.NotNil(t, record)

		value := &Invitation{
			Label: "sample-label2",
		}
		err := record.SaveInvitation(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty bytes")
	})
}

func TestConnectionRecorder_GetInvitation(t *testing.T) {
	t.Run("test get invitation - success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(nil, store, nil)
		require.NotNil(t, record)

		valueStored := &Invitation{
			ID:    "sample-id-3",
			Label: "sample-label-3",
		}

		err := record.SaveInvitation(valueStored)
		require.NoError(t, err)

		valueFound, err := record.GetInvitation(valueStored.ID)
		require.NoError(t, err)
		require.Equal(t, valueStored, valueFound)
	})

	t.Run("test get invitation - not found scenario", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(nil, store, nil)
		require.NotNil(t, record)

		valueFound, err := record.GetInvitation("sample-key4")
		require.Error(t, err)
		require.Equal(t, err, storage.ErrDataNotFound)
		require.Nil(t, valueFound)
	})

	t.Run("test get invitation - invalid key scenario", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(nil, store, nil)
		require.NotNil(t, record)

		valueFound, err := record.GetInvitation("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty bytes")
		require.Nil(t, valueFound)
	})
}

func TestConnectionRecorder_GetConnectionRecord(t *testing.T) {
	t.Run("test success found data in transient store ", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, store, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ConnectionID: connIDValue, ThreadID: threadIDValue,
			Namespace: myNSPrefix}
		connRecBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		connKey := connectionKeyPrefix(connIDValue)
		require.NoError(t, transientStore.Put(connKey, connRecBytes))
		nsThreadID, err := createNSKey(myNSPrefix, threadIDValue)
		require.NoError(t, err)
		require.NoError(t, transientStore.Put(nsThreadID, []byte(connIDValue)))

		storedConnRec, err := record.GetConnectionRecord(connIDValue)
		require.NoError(t, err)
		require.Equal(t, storedConnRec, connRec)
	})
	t.Run("test success found data in store ", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, store, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ConnectionID: connIDValue, ThreadID: threadIDValue,
			Namespace: myNSPrefix}
		connRecBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		connKey := connectionKeyPrefix(connIDValue)
		require.NoError(t, store.Put(connKey, connRecBytes))
		nsThreadID, err := createNSKey(myNSPrefix, threadIDValue)
		require.NoError(t, err)
		require.NoError(t, store.Put(nsThreadID, []byte(connIDValue)))

		storedConnRec, err := record.GetConnectionRecord(connIDValue)
		require.NoError(t, err)
		require.Equal(t, storedConnRec, connRec)
	})
	t.Run("test error from transient store", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{
			Store:  make(map[string][]byte),
			ErrGet: fmt.Errorf("get error transientstore")}
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, store, nil)
		require.NotNil(t, record)
		connRecBytes, err := json.Marshal(&ConnectionRecord{ConnectionID: connIDValue, ThreadID: threadIDValue,
			Namespace: myNSPrefix})
		require.NoError(t, err)
		connKey := connectionKeyPrefix(connIDValue)
		require.NoError(t, transientStore.Put(connKey, connRecBytes))
		_, err = record.GetConnectionRecord(connIDValue)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error transientstore")
	})
	t.Run("test error from store", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		store := &mockstorage.MockStore{Store: make(map[string][]byte), ErrGet: fmt.Errorf("get error store")}
		record := NewConnectionRecorder(transientStore, store, nil)
		require.NotNil(t, record)
		connRecBytes, err := json.Marshal(&ConnectionRecord{ConnectionID: connIDValue, ThreadID: threadIDValue,
			Namespace: myNSPrefix})
		require.NoError(t, err)
		connKey := connectionKeyPrefix(connIDValue)
		require.NoError(t, store.Put(connKey, connRecBytes))
		_, err = record.GetConnectionRecord(connIDValue)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error store")
	})
}

func TestConnectionRecordByState(t *testing.T) {
	transientStore := &mockstorage.MockStore{Store: make(map[string][]byte), ErrGet: nil}
	record := NewConnectionRecorder(transientStore, nil, nil)
	require.NotNil(t, record)

	connRec := &ConnectionRecord{ConnectionID: generateRandomID(), ThreadID: threadIDValue,
		Namespace: myNSPrefix, State: "requested"}
	err := record.saveConnectionRecord(connRec)
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
	connRec = &ConnectionRecord{ConnectionID: generateRandomID(), ThreadID: threadIDValue,
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
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, store, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.NoError(t, err)

		storedRecord, err := record.GetConnectionRecord(connRec.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run("save connection record and fetch from no namespace error", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, nil, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited}
		err := record.saveNewConnectionRecord(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty")
	})
	t.Run("save connection record error", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: fmt.Errorf("get error")}
		record := NewConnectionRecorder(transientStore, nil, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: "",
			ConnectionID: "test", State: stateNameInvited, Namespace: theirNSPrefix}
		err := record.saveConnectionRecord(connRec)
		require.Contains(t, err.Error(), "get error")
	})
	t.Run("save connection record error", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: fmt.Errorf("get error")}
		record := NewConnectionRecorder(transientStore, nil, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.Contains(t, err.Error(), "get error")
	})
	t.Run("save connection record in permanent store error", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		store := &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: fmt.Errorf("get error")}
		record := NewConnectionRecorder(transientStore, store, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameCompleted, Namespace: theirNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.Contains(t, err.Error(), "get error")
	})
	t.Run("error saving DID", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, store, &mockdidconnection.MockDIDConnection{
			SaveConnectionErr: fmt.Errorf("save error"),
		})
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameCompleted, Namespace: theirNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "save error")

		// note: record is still stored, since error happens afterwards
		storedRecord, err := record.GetConnectionRecord(connRec.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run("error saving DID by resolving", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, store, &mockdidconnection.MockDIDConnection{
			ResolveDIDErr: fmt.Errorf("save error"),
		})
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue, MyDID: "did:foo",
			ConnectionID: connIDValue, State: stateNameCompleted, Namespace: theirNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
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
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, nil, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: myNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.NoError(t, err)

		nsThreadID, err := createNSKey(myNSPrefix, threadIDValue)
		require.NoError(t, err)

		storedRecord, err := record.GetConnectionRecordByNSThreadID(nsThreadID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run(" get connection record by namespace threadID their namespace", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, nil, nil)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.NoError(t, err)

		nsThreadID, err := createNSKey(theirNSPrefix, threadIDValue)
		require.NoError(t, err)

		storedRecord, err := record.GetConnectionRecordByNSThreadID(nsThreadID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run(" data not found error due to missing input parameter", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, nil, nil)
		require.NotNil(t, record)
		connRec, err := record.GetConnectionRecordByNSThreadID("")
		require.Contains(t, err.Error(), "data not found")
		require.Nil(t, connRec)
	})
}

func TestConnectionRecorder_PrepareConnectionRecord(t *testing.T) {
	t.Run(" prepare connection record  error", func(t *testing.T) {
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, nil, nil)
		require.NotNil(t, record)
		connRec, err := prepareConnectionRecord(nil)
		require.Contains(t, err.Error(), "prepare connection record")
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
		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(transientStore, nil, nil)
		require.NotNil(t, record)
		err := record.saveNSThreadID("", theirNSPrefix, connIDValue)
		require.Error(t, err)
		err = record.saveNSThreadID("", myNSPrefix, connIDValue)
		require.Error(t, err)
		err = record.saveNSThreadID(threadIDValue, "", connIDValue)
		require.Error(t, err)
	})
}

func TestConnectionRecorder_QueryConnectionRecord(t *testing.T) {
	t.Run("test query connection record", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}

		transientStore, err := mem.NewProvider().OpenStore(DIDExchange)
		require.NoError(t, err)

		const (
			storeCount          = 5
			overlap             = 3
			transientStoreCount = 4
		)

		for i := 0; i < storeCount+overlap; i++ {
			val, jsonErr := json.Marshal(&ConnectionRecord{
				ConnectionID: string(i),
			})
			require.NoError(t, jsonErr)

			err = store.Put(fmt.Sprintf("%s_abc%d", connIDKeyPrefix, i), val)
			require.NoError(t, err)
		}
		for i := overlap; i < transientStoreCount+storeCount; i++ {
			val, jsonErr := json.Marshal(&ConnectionRecord{
				ConnectionID: string(i),
			})
			require.NoError(t, jsonErr)

			err = transientStore.Put(fmt.Sprintf("%s_abc%d", connIDKeyPrefix, i), val)
			require.NoError(t, err)
		}

		recorder := NewConnectionRecorder(transientStore, store, nil)
		require.NotNil(t, recorder)
		result, err := recorder.QueryConnectionRecords()
		require.NoError(t, err)
		require.Len(t, result, storeCount+transientStoreCount)
	})

	t.Run("test query connection record failure", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		err := store.Put(fmt.Sprintf("%s_abc123", connIDKeyPrefix), []byte("-----"))
		require.NoError(t, err)

		recorder := NewConnectionRecorder(nil, store, nil)
		require.NotNil(t, recorder)
		result, err := recorder.QueryConnectionRecords()
		require.Error(t, err)
		require.Empty(t, result)
	})
}
