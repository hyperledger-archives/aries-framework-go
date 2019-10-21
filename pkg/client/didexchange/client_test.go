/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/common/did"
	mockprotocol "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		_, err = New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(), ServiceValue: svc})
		require.NoError(t, err)
	})

	t.Run("test error from get service from context", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceErr: fmt.Errorf("service error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})

	t.Run("test error from cast service", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceValue: nil})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to DIDExchange Service failed")
	})
}

func TestClient_CreateInvitation(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(), ServiceValue: svc,
			WalletValue: &mockwallet.CloseableWallet{CreateEncryptionKeyValue: "sample-key"}, InboundEndpointValue: "endpoint"})

		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation("agent")
		require.NoError(t, err)
		require.NotNil(t, inviteReq)
		require.NotEmpty(t, inviteReq.Label)
		require.NotEmpty(t, inviteReq.ID)
		require.Equal(t, "endpoint", inviteReq.ServiceEndpoint)
	})

	t.Run("test error from createSigningKey", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(), ServiceValue: svc,
			WalletValue: &mockwallet.CloseableWallet{CreateEncryptionKeyErr: fmt.Errorf("createEncryptionKeyErr")}})
		require.NoError(t, err)
		_, err = c.CreateInvitation("agent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "createEncryptionKeyErr")
	})

	t.Run("test error from save record", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		store := &mockstore.MockStore{Store: make(map[string][]byte)}
		store.ErrPut = errors.New("store error")
		c, err := New(&mockprovider.Provider{StorageProviderValue: &mockstore.MockStoreProvider{Custom: store},
			ServiceValue: svc, WalletValue: &mockwallet.CloseableWallet{}})
		require.NoError(t, err)
		_, err = c.CreateInvitation("agent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save invitation")
	})
}

func TestClient_CreateInvitationWithDID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			ServiceValue:         svc,
			WalletValue:          &mockwallet.CloseableWallet{CreateEncryptionKeyValue: "sample-key"},
			InboundEndpointValue: "endpoint"})
		require.NoError(t, err)

		const label = "agent"
		const id = "did:sidetree:123"
		inviteReq, err := c.CreateInvitationWithDID(label, id)
		require.NoError(t, err)
		require.NotNil(t, inviteReq)
		require.Equal(t, label, inviteReq.Label)
		require.NotEmpty(t, inviteReq.ID)
		require.Equal(t, id, inviteReq.DID)
	})
	t.Run("test error from save invitation", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		store := &mockstore.MockStore{Store: make(map[string][]byte)}
		store.ErrPut = errors.New("store error")
		c, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Custom: store},
			ServiceValue:         svc,
			WalletValue:          &mockwallet.CloseableWallet{}})
		require.NoError(t, err)

		_, err = c.CreateInvitationWithDID("agent", "did:sidetree:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save invitation")
	})
}

func TestClient_QueryConnectionByID(t *testing.T) {
	connID := "id1"
	threadID := "thid1"
	t.Run("test success", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)
		s := &mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &didexchange.ConnectionRecord{ConnectionID: connID, ThreadID: threadID, State: "complete"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, s.Put("conn_id1", connBytes))
		h := crypto.SHA256.New()
		hash := h.Sum([]byte(connRec.ThreadID))
		key := fmt.Sprintf("%x", hash)
		require.NoError(t, s.Put("my_"+key, []byte(connRec.ConnectionID)))
		c := didexchange.NewConnectionRecorder(s)
		result, err := c.GetConnectionRecord(threadID, "my")
		require.NoError(t, err)
		require.Equal(t, "complete", result.State)
		require.Equal(t, "id1", result.ConnectionID)
	})

	t.Run("test error", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)
		s := mockstore.MockStore{Store: make(map[string][]byte),
			ErrGet: fmt.Errorf("query connection error")}
		connRec := &didexchange.ConnectionRecord{ConnectionID: connID, ThreadID: threadID, State: "complete"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, s.Put("conn_id1", connBytes))
		c := didexchange.NewConnectionRecorder(&s)
		_, err = c.GetConnectionRecord(threadID, "my")
		require.Error(t, err)
	})

	t.Run("test connection not found", func(t *testing.T) {
		svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)
		s := mockstore.MockStore{ErrGet: storage.ErrDataNotFound}
		c, err := New(&mockprovider.Provider{
			ServiceValue:         svc,
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &s}})
		require.NoError(t, err)

		_, err = c.GetConnectionRecord("id1")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrConnectionNotFound))
	})
}

func TestClient_RemoveConnection(t *testing.T) {
	svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(), ServiceValue: svc})
	require.NoError(t, err)

	err = c.RemoveConnection("sample-id")
	require.NoError(t, err)
}

func TestClient_HandleInvitation(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
			ServiceValue: &mockprotocol.MockDIDExchangeSvc{},
			WalletValue:  &mockwallet.CloseableWallet{CreateEncryptionKeyValue: "sample-key"}, InboundEndpointValue: "endpoint"})

		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation("agent")
		require.NoError(t, err)
		require.NoError(t, c.HandleInvitation(inviteReq))
	})

	t.Run("test error from handle msg", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
			ServiceValue: &mockprotocol.MockDIDExchangeSvc{HandleFunc: func(msg service.DIDCommMsg) error {
				return fmt.Errorf("handle error")
			}},
			WalletValue: &mockwallet.CloseableWallet{CreateEncryptionKeyValue: "sample-key"}, InboundEndpointValue: "endpoint"})
		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation("agent")
		require.NoError(t, err)
		err = c.HandleInvitation(inviteReq)
		require.Error(t, err)
		require.Contains(t, err.Error(), "handle error")
	})
}

func TestClient_QueryConnectionsByParams(t *testing.T) {
	svc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: svc})
	require.NoError(t, err)

	results, err := c.QueryConnections(&QueryConnectionsParams{InvitationKey: "sample-inv-key"})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	for _, result := range results {
		require.NotNil(t, result)
		require.NotNil(t, result.ConnectionID)
	}
}

func TestServiceEvents(t *testing.T) {
	store := &mockstore.MockStore{Store: make(map[string][]byte)}
	didExSvc, err := didexchange.New(&did.MockDIDCreator{}, &mockprotocol.MockProvider{CustomStore: store})
	require.NoError(t, err)

	// create the client
	c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(), ServiceValue: didExSvc})
	require.NoError(t, err)
	require.NotNil(t, c)

	// register action event channel
	aCh := make(chan service.DIDCommAction, 10)
	err = c.RegisterActionEvent(aCh)
	require.NoError(t, err)
	go func() {
		require.NoError(t, service.AutoExecuteActionEvent(aCh))
	}()

	// register message event channel
	mCh := make(chan service.StateMsg, 10)
	err = c.RegisterMsgEvent(mCh)
	require.NoError(t, err)
	go func() {
		for e := range mCh {
			fmt.Println("message = ", e.Type)
		}
	}()

	// send connection request message
	id := "valid-thread-id"
	newDidDoc, err := (&did.MockDIDCreator{}).CreateDID()
	require.NoError(t, err)

	request, err := json.Marshal(
		&didexchange.Request{
			Type:  didexchange.ConnectionRequest,
			ID:    id,
			Label: "test",
			Connection: &didexchange.Connection{
				DID:    "B.did@B:A",
				DIDDoc: newDidDoc,
			},
		},
	)
	require.NoError(t, err)
	msg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)
	err = didExSvc.HandleInbound(msg)
	require.NoError(t, err)

	validateState(t, store, id, "responded", 100*time.Millisecond)
}

func validateState(t *testing.T, store storage.Store, id, expected string, timeoutDuration time.Duration) {
	actualState := ""
	timeout := time.After(timeoutDuration)
	for {
		select {
		case <-timeout:
			require.Fail(t, fmt.Sprintf("id=%s expectedState=%s actualState=%s", id, expected, actualState))
			return
		default:
			r := didexchange.NewConnectionRecorder(store)
			cr, err := r.GetConnectionRecord(id, "their")
			if err != nil || expected != cr.State {
				continue
			}
			return
		}
	}
}

func TestServiceEventError(t *testing.T) {
	didExSvc := mockprotocol.MockDIDExchangeSvc{
		ProtocolName:           didexchange.DIDExchange,
		RegisterActionEventErr: errors.New("action event registration failed"),
		RegisterMsgEventErr:    errors.New("msg event registration failed"),
	}

	// register action event on service throws error
	_, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(), ServiceValue: &didExSvc})
	require.Error(t, err)
	require.Contains(t, err.Error(), "didexchange action event "+
		"registration: action event registration failed")

	// register msg event on service throws error
	didExSvc.RegisterActionEventErr = nil
	_, err = New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(), ServiceValue: &didExSvc})
	require.Error(t, err)
	require.Contains(t, err.Error(), "didexchange message event "+
		"registration: msg event registration failed")
}

func TestService_ActionEvent(t *testing.T) {
	c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: &mockprotocol.MockDIDExchangeSvc{}})
	require.NoError(t, err)

	// validate before register
	require.Nil(t, c.actionEvent)

	// register an action event
	ch := make(chan service.DIDCommAction)
	err = c.RegisterActionEvent(ch)
	require.NoError(t, err)

	// register another action event
	err = c.RegisterActionEvent(make(chan service.DIDCommAction))
	require.Error(t, err)
	require.Contains(t, err.Error(), "channel is already registered for the action event")

	// validate after register
	require.NotNil(t, c.actionEvent)

	// unregister a action event
	err = c.UnregisterActionEvent(ch)
	require.NoError(t, err)

	// validate after unregister
	require.Nil(t, c.actionEvent)

	// unregister with different channel
	err = c.UnregisterActionEvent(make(chan service.DIDCommAction))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid channel passed to unregister the action event")
}

func TestService_MsgEvents(t *testing.T) {
	c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: &mockprotocol.MockDIDExchangeSvc{}})
	require.NoError(t, err)

	// validate before register
	require.Nil(t, c.msgEvents)
	require.Equal(t, 0, len(c.msgEvents))

	// register a status event
	ch := make(chan service.StateMsg)
	err = c.RegisterMsgEvent(ch)
	require.NoError(t, err)

	// validate after register
	require.NotNil(t, c.msgEvents)
	require.Equal(t, 1, len(c.msgEvents))

	// register a new status event
	err = c.RegisterMsgEvent(make(chan service.StateMsg))
	require.NoError(t, err)

	// validate after new register
	require.NotNil(t, c.msgEvents)
	require.Equal(t, 2, len(c.msgEvents))

	// unregister a status event
	err = c.UnregisterMsgEvent(ch)
	require.NoError(t, err)

	// validate after unregister
	require.Equal(t, 1, len(c.msgEvents))

	// add channels and remove in opposite order
	c.msgEvents = nil
	ch1 := make(chan service.StateMsg)
	ch2 := make(chan service.StateMsg)
	ch3 := make(chan service.StateMsg)

	err = c.RegisterMsgEvent(ch1)
	require.NoError(t, err)

	err = c.RegisterMsgEvent(ch2)
	require.NoError(t, err)

	err = c.RegisterMsgEvent(ch3)
	require.NoError(t, err)

	err = c.UnregisterMsgEvent(ch3)
	require.NoError(t, err)

	err = c.UnregisterMsgEvent(ch2)
	require.NoError(t, err)

	err = c.UnregisterMsgEvent(ch1)
	require.NoError(t, err)
}
