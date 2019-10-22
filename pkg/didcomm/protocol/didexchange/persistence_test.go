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

func TestConnectionRecord_SaveInvitation(t *testing.T) {
	t.Run("test save invitation success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
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
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)

		value := &Invitation{
			Label: "sample-label2",
		}
		err := record.SaveInvitation(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty bytes")
		require.Empty(t, store.Store)
	})
}

func TestConnectionRecorder_GetInvitation(t *testing.T) {
	t.Run("test get invitation - success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
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
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)

		valueFound, err := record.GetInvitation("sample-key4")
		require.Error(t, err)
		require.Equal(t, err, storage.ErrDataNotFound)
		require.Nil(t, valueFound)
	})

	t.Run("test get invitation - invalid key scenario", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)

		valueFound, err := record.GetInvitation("")
		require.Contains(t, err.Error(), "empty bytes")
		require.Nil(t, valueFound)
	})
}

func TestConnectionRecorder_GetConnectionRecord(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
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
	t.Run("test error", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte), ErrGet: fmt.Errorf("get error")}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		connRecBytes, err := json.Marshal(&ConnectionRecord{ConnectionID: connIDValue, ThreadID: threadIDValue,
			Namespace: myNSPrefix})
		require.NoError(t, err)
		connKey := connectionKeyPrefix(connIDValue)
		require.NoError(t, store.Put(connKey, connRecBytes))
		_, err = record.GetConnectionRecord(connIDValue)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error")
	})
}

func TestConnectionRecorder_SaveConnectionRecord(t *testing.T) {
	t.Run("save connection record and get connection Record success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
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
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited}
		err := record.saveNewConnectionRecord(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty")
	})
	t.Run("save connection record error", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: fmt.Errorf("get error")}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: "",
			ConnectionID: "test", State: stateNameInvited, Namespace: theirNSPrefix}
		err := record.saveConnectionRecord(connRec)
		require.Contains(t, err.Error(), "get error")
	})
	t.Run("save connection record error", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: fmt.Errorf("get error")}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.Contains(t, err.Error(), "get error")
	})
}
func TestConnectionRecorder_GetConnectionRecordByNSThreadID(t *testing.T) {
	t.Run(" get connection record by namespace threadID in my namespace", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
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
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
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
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		connRec, err := record.GetConnectionRecordByNSThreadID("")
		require.Contains(t, err.Error(), "data not found")
		require.Nil(t, connRec)
	})
}
func TestConnectionRecorder_PrepareConnectionRecord(t *testing.T) {
	t.Run(" prepare connection record  error", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
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
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		err := record.saveNSThreadID("", theirNSPrefix, connIDValue)
		require.Error(t, err)
		err = record.saveNSThreadID("", myNSPrefix, connIDValue)
		require.Error(t, err)
		err = record.saveNSThreadID(threadIDValue, "", connIDValue)
		require.Error(t, err)
	})
}
