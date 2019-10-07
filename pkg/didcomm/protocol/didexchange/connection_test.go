/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
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
	store := &storage.MockStore{Store: make(map[string][]byte)}
	record := NewConnectionRecorder(store)
	require.NotNil(t, record)

	key := "sample-key"
	value := struct {
		Code    int
		Message string
	}{
		Code:    1,
		Message: "sample-msg",
	}

	err := record.SaveInvitation(key, value)
	require.NoError(t, err)

	require.NotEmpty(t, store)

	k, err := computeHash([]byte(key))
	require.NoError(t, err)
	require.NotEmpty(t, k)

	v, err := record.store.Get(k)
	require.NoError(t, err)
	require.NotEmpty(t, v)
}

func TestConnectionRecord_SaveInvitationError(t *testing.T) {
	store := &storage.MockStore{Store: make(map[string][]byte)}
	record := NewConnectionRecorder(store)
	require.NotNil(t, record)

	key := ""
	value := struct {
		Code    int
		Message string
	}{
		Code:    1,
		Message: "sample-msg",
	}

	err := record.SaveInvitation(key, value)
	require.Error(t, err)
	require.Empty(t, store.Store)

	key = "sample-key"
	valueE := struct {
		Code int
		Ch   chan bool
	}{
		Code: 1,
		Ch:   make(chan bool),
	}

	err = record.SaveInvitation(key, valueE)
	require.Error(t, err)
	require.Empty(t, store.Store)
}

func TestSaveConnectionRecord(t *testing.T) {
	t.Run("save connection record", func(t *testing.T) {
		store := &storage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		payloadBytes, err := json.Marshal(
			&Invitation{
				Type:            ConnectionInvite,
				ID:              randomString(),
				Label:           "Bob",
				DID:             "did:example:bob",
				ServiceEndpoint: "serviceEndpoint",
				RecipientKeys:   []string{"Receipt keys"},
			},
		)
		require.NoError(t, err)
		msg := &Message{Msg: dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: payloadBytes}, ThreadID: "xyz", ConnectionID: "connID", State: stateNameInvited}
		err = record.SaveConnectionRecorder(msg)
		require.NoError(t, err)

		state, err := record.FindByConnectionID(msg.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, stateNameInvited,state)
	})
	t.Run("save connection record error", func(t *testing.T) {
		store := &storage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		msg := &Message{Msg: dispatcher.DIDCommMsg{Type: ConnectionRequest,}, ThreadID: "xyz", ConnectionID: "connID", State: "invited"}
		err := record.SaveConnectionRecorder(msg)
		require.Error(t, err)
	})
	t.Run("save connection record error", func(t *testing.T) {
		store := &storage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		payloadBytes, err := json.Marshal(
			&Invitation{
				Type:            ConnectionInvite,
				ID:              randomString(),
				Label:           "Bob",
				DID:             "did:example:bob",
			},
		)
		require.NoError(t, err)
		msg := &Message{Msg: dispatcher.DIDCommMsg{Type: ConnectionRequest,Payload:payloadBytes}, ThreadID: "xyz", ConnectionID: "", State: "invited"}
		err = record.SaveConnectionRecorder(msg)
		require.Error(t, err)
	})
}
func TestSaveProtocolID(t *testing.T) {
	t.Run("save protocol id record", func(t *testing.T) {
		store := &storage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		request := &Request{
			Type:  ConnectionRequest,
			ID:    "",
			Label: "Bob",
			Connection: &Connection{
				DID:    "B.did@B:A",
			},
		}
		payloadBytes, err := json.Marshal(request)
		require.NoError(t, err)
		msg := &Message{Msg: dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: payloadBytes}, ThreadID: "xyz", ConnectionID: "1234456777", State: "invited"}
		err = record.SaveProtocolID("", msg)
		require.NoError(t, err)

		thid := msg.ThreadID
		myDID := request.Connection.DID
		connID, err := record.FindByProtocolID(myDID, thid)
		require.NoError(t, err)
		require.NotNil(t, connID)
		require.Equal(t, "1234456777", connID)
	})
	t.Run("save protocol id record without payload", func(t *testing.T) {
		store := &storage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		msg := &Message{Msg: dispatcher.DIDCommMsg{Type: ConnectionRequest,}, ThreadID: "xyz", ConnectionID: "connID", State: "invited"}
		err := record.SaveProtocolID("xyz", msg)
		require.NoError(t, err)
	})
	t.Run("save protocol id record error", func(t *testing.T) {
		store := &storage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		msg := &Message{Msg: dispatcher.DIDCommMsg{Type: ConnectionRequest,}, ThreadID: "", ConnectionID: "connID", State: "invited"}
		err := record.SaveProtocolID("", msg)
		require.Error(t, err)
	})
	t.Run("save protocol id record error", func(t *testing.T) {
		store := &storage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		require.NotNil(t, record)
		request := &Request{
			Type:  ConnectionRequest,
			ID:    "",
			Label: "Bob",
			Connection: &Connection{
				DID:    "",
			},
		}
		payloadBytes, err := json.Marshal(request)
		require.NoError(t, err)
		msg := &Message{Msg: dispatcher.DIDCommMsg{Type: ConnectionRequest,Payload:payloadBytes}, ThreadID: "", ConnectionID: "connID", State: "invited"}
		err = record.SaveProtocolID("", msg)
		require.Error(t, err)
	})

}
func TestFindByProtocolID(t *testing.T) {
	t.Run("find by protocol ID error", func(t *testing.T) {
		store := &storage.MockStore{Store: make(map[string][]byte)}
		record := NewConnectionRecorder(store)
		thid := ""
		myDID := ""
		_, err := record.FindByProtocolID(myDID, thid)
		require.Error(t, err)

	})

}
