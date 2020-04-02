/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
)

const (
	threadIDValue = "xyz"
	connIDValue   = "connValue"
)

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

func TestConnectionRecorder_SaveConnectionRecord(t *testing.T) {
	t.Run("save connection record and get connection Record success", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		connRec := &connection.Record{ThreadID: threadIDValue,

			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err = record.saveConnectionRecordWithMapping(connRec)
		require.NoError(t, err)

		storedRecord, err := record.GetConnectionRecord(connRec.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run("save connection record and fetch from no namespace error", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		connRec := &connection.Record{ThreadID: threadIDValue,

			ConnectionID: connIDValue, State: stateNameInvited}
		err = record.saveConnectionRecordWithMapping(connRec)
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
		connRec := &connection.Record{ThreadID: "",
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
		connRec := &connection.Record{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err = record.saveConnectionRecordWithMapping(connRec)
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
		connRec := &connection.Record{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameCompleted, Namespace: theirNSPrefix}
		err = record.saveConnectionRecordWithMapping(connRec)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("save with mapping - error saving DID by resolving", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)

		record.ConnectionStore, err = did.NewConnectionStore(&protocol.MockProvider{
			CustomVDRI: &vdri.MockVDRIRegistry{
				ResolveErr: fmt.Errorf("resolve error"),
			},
		})

		require.NotNil(t, record)
		require.NoError(t, err)

		connRec := &connection.Record{ThreadID: threadIDValue, MyDID: "did:foo",
			ConnectionID: connIDValue, State: stateNameCompleted, Namespace: theirNSPrefix}
		err = record.saveConnectionRecordWithMapping(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")

		// note: record is still stored, since error happens afterwards
		storedRecord, err := record.GetConnectionRecord(connRec.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run("error saving DID by resolving", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)

		record.ConnectionStore, err = did.NewConnectionStore(&protocol.MockProvider{
			CustomVDRI: &vdri.MockVDRIRegistry{
				ResolveErr: fmt.Errorf("resolve error"),
			},
		})
		require.NotNil(t, record)
		require.NoError(t, err)

		connRec := &connection.Record{ThreadID: threadIDValue, MyDID: "did:foo",
			ConnectionID: connIDValue, State: stateNameCompleted, Namespace: theirNSPrefix}
		err = record.saveConnectionRecord(connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")

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
		connRec := &connection.Record{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: myNSPrefix}
		err = record.saveConnectionRecordWithMapping(connRec)
		require.NoError(t, err)

		nsThreadID, err := connection.CreateNamespaceKey(myNSPrefix, threadIDValue)
		require.NoError(t, err)

		storedRecord, err := record.GetConnectionRecordByNSThreadID(nsThreadID)
		require.NoError(t, err)
		require.Equal(t, connRec, storedRecord)
	})
	t.Run(" get connection record by namespace threadID their namespace", func(t *testing.T) {
		record, err := newConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, record)
		connRec := &connection.Record{ThreadID: threadIDValue,
			ConnectionID: connIDValue, State: stateNameInvited, Namespace: theirNSPrefix}
		err = record.saveConnectionRecordWithMapping(connRec)
		require.NoError(t, err)

		nsThreadID, err := connection.CreateNamespaceKey(theirNSPrefix, threadIDValue)
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
