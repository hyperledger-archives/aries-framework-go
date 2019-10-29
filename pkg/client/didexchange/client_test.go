/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	mockprotocol "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockcreator "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdr/didcreator"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
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
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
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
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(), ServiceValue: svc,
			WalletValue: &mockwallet.CloseableWallet{CreateKeyErr: fmt.Errorf("createKeyErr")}})
		require.NoError(t, err)
		_, err = c.CreateInvitation("agent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "createKeyErr")
	})

	t.Run("test error from save record", func(t *testing.T) {
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		store := mockstore.NewMockStoreProvider()
		store.Store.ErrPut = errors.New("store error")
		c, err := New(&mockprovider.Provider{StorageProviderValue: store,
			ServiceValue: svc, WalletValue: &mockwallet.CloseableWallet{}})
		require.NoError(t, err)
		_, err = c.CreateInvitation("agent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save invitation")
	})
}

func TestClient_CreateInvitationWithDID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
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
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		store := mockstore.NewMockStoreProvider()
		store.Store.ErrPut = errors.New("store error")
		c, err := New(&mockprovider.Provider{
			StorageProviderValue: store,
			ServiceValue:         svc,
			WalletValue:          &mockwallet.CloseableWallet{}})
		require.NoError(t, err)

		_, err = c.CreateInvitationWithDID("agent", "did:sidetree:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save invitation")
	})
}

func TestClient_QueryConnectionByID(t *testing.T) {
	const connID = "id1"
	const threadID = "thid1"
	t.Run("test success", func(t *testing.T) {
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)
		s := &mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &didexchange.ConnectionRecord{ConnectionID: connID, ThreadID: threadID, State: "complete"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, err)
		require.NoError(t, s.Put("conn_id1", connBytes))
		c := didexchange.NewConnectionRecorder(s)
		result, err := c.GetConnectionRecord(connID)
		require.NoError(t, err)
		require.Equal(t, "complete", result.State)
		require.Equal(t, "id1", result.ConnectionID)
	})

	t.Run("test error", func(t *testing.T) {
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)
		s := &mockstore.MockStore{Store: make(map[string][]byte),
			ErrGet: fmt.Errorf("query connection error")}
		connRec := &didexchange.ConnectionRecord{ConnectionID: connID, ThreadID: threadID, State: "complete"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		c := didexchange.NewConnectionRecorder(s)
		require.NoError(t, s.Put("conn_id1", connBytes))
		_, err = c.GetConnectionRecord(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "query connection error")
	})

	t.Run("test data not found", func(t *testing.T) {
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})

		require.NoError(t, err)
		require.NotNil(t, svc)
		s := mockstore.MockStore{ErrGet: storage.ErrDataNotFound}
		require.NoError(t, err)
		c := didexchange.NewConnectionRecorder(&s)
		_, err = c.GetConnectionRecord(connID)
		require.Error(t, err)
		require.True(t, errors.Is(err, storage.ErrDataNotFound))
	})
}

func TestClient_GetConnection(t *testing.T) {
	connID := "id1"
	threadID := "thid1"
	t.Run("test failure", func(t *testing.T) {
		svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, svc)
		s := &mockstore.MockStore{Store: make(map[string][]byte), ErrGet: ErrConnectionNotFound}
		c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
			ServiceValue: svc})
		require.NoError(t, err)
		connRec := &didexchange.ConnectionRecord{ConnectionID: connID, ThreadID: threadID, State: "complete"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, s.Put("conn_id1", connBytes))
		result, err := c.GetConnection(connID)
		require.Equal(t, err.Error(), ErrConnectionNotFound.Error())
		require.Nil(t, result)
	})
}

func TestClientGetConnectionAtState(t *testing.T) {
	// create service
	svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
	require.NoError(t, err)
	require.NotNil(t, svc)

	// create client
	c, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: svc})
	require.NoError(t, err)

	// not found
	result, err := c.GetConnectionAtState("id1", "complete")
	require.Equal(t, err.Error(), ErrConnectionNotFound.Error())
	require.Nil(t, result)
}

func TestClient_RemoveConnection(t *testing.T) {
	svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
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
			ServiceValue: &mockprotocol.MockDIDExchangeSvc{HandleFunc: func(msg *service.DIDCommMsg) error {
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
	svc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{})
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
	store := mockstore.NewMockStoreProvider()
	didExSvc, err := didexchange.New(&mockcreator.MockDIDCreator{}, &mockprotocol.MockProvider{StoreProvider: store})
	require.NoError(t, err)

	// create the client
	c, err := New(&mockprovider.Provider{StorageProviderValue: store, ServiceValue: didExSvc})
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

	stateMsg := make(chan service.StateMsg)
	go func() {
		for e := range mCh {
			if e.Type == service.PostState && e.StateID == "responded" {
				stateMsg <- e
			}
		}
	}()

	// send connection request message
	id := "valid-thread-id"
	newDidDoc, err := (&mockcreator.MockDIDCreator{}).Create("test")
	require.NoError(t, err)

	request, err := json.Marshal(
		&didexchange.Request{
			Type:  didexchange.RequestMsgType,
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

	select {
	case e := <-stateMsg:
		switch v := e.Properties.(type) {
		case Event:
			props := v
			conn, err := c.GetConnectionAtState(props.ConnectionID(), e.StateID)
			require.NoError(t, err)
			require.Equal(t, e.StateID, conn.State)
		default:
			require.Fail(t, "unable to cast to did exchange event")
		}
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated due to timeout")
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
	require.Nil(t, c.ActionEvent())

	// register an action event
	ch := make(chan service.DIDCommAction)
	err = c.RegisterActionEvent(ch)
	require.NoError(t, err)

	// register another action event
	err = c.RegisterActionEvent(make(chan service.DIDCommAction))
	require.Error(t, err)
	require.Contains(t, err.Error(), "channel is already registered for the action event")

	// validate after register
	require.NotNil(t, c.ActionEvent())

	// unregister a action event
	err = c.UnregisterActionEvent(ch)
	require.NoError(t, err)

	// validate after unregister
	require.Nil(t, c.ActionEvent())

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
	require.Nil(t, c.MsgEvents())
	require.Equal(t, 0, len(c.MsgEvents()))

	// register a status event
	ch := make(chan service.StateMsg)
	err = c.RegisterMsgEvent(ch)
	require.NoError(t, err)

	// validate after register
	require.NotNil(t, c.MsgEvents())
	require.Equal(t, 1, len(c.MsgEvents()))

	// register a new status event
	err = c.RegisterMsgEvent(make(chan service.StateMsg))
	require.NoError(t, err)

	// validate after new register
	require.NotNil(t, c.MsgEvents())
	require.Equal(t, 2, len(c.MsgEvents()))

	// unregister a status event
	err = c.UnregisterMsgEvent(ch)
	require.NoError(t, err)

	// validate after unregister
	require.Equal(t, 1, len(c.MsgEvents()))
}
