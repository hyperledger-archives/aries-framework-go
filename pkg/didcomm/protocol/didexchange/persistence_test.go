/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
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

func TestConnectionRecorder_GetConnection(t *testing.T) {
	t.Run("test error", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte), ErrGet: fmt.Errorf("get error")}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		require.NoError(t, store.Put("key1", []byte("value1")))
		_, err := record.GetConnectionRecord("key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error")
	})
}

func TestConnectionRecorder_SaveConnectionRecord(t *testing.T) {
	t.Run("save connection record and get connection Record from my namespace success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.NoError(t, err)

		// get the prefixed hashed threadID
		thid, err := createTheirNSKey(threadIDValue)
		require.NoError(t, err)
		storedRecord, err := record.GetConnectionRecord(thid)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run("save connection record and fetch from their namespace success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		connRec := &ConnectionRecord{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: myNSPrefix}
		err := record.saveNewConnectionRecord(connRec)
		require.NoError(t, err)

		err = record.saveConnectionRecord(connRec)
		require.NoError(t, err)

		// get the prefixed and hashed threadID
		thid, err := createMyNSKey(threadIDValue)
		require.NoError(t, err)
		storedRecord, err := record.GetConnectionRecord(thid)
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
}
func TestConnectionRecorder_GetConnectionID(t *testing.T) {
	t.Run(" get connection ID empty bytes error", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
	})
}
func TestConnectionRecorder_CreateTheirNSkey(t *testing.T) {
	t.Run(" creating their name space key success", func(t *testing.T) {
		key, err := createTheirNSKey(threadIDValue)
		require.NoError(t, err)
		require.NotNil(t, key)
	})
	t.Run(" check error while creating their name space key", func(t *testing.T) {
		_, err := createTheirNSKey("")
		require.Error(t, err)
	})
}
