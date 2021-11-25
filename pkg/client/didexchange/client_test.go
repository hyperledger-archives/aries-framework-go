/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockprotocol "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		_, err = New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
		})
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

	t.Run("test route service cast error", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mocksvc.MockDIDExchangeSvc{},
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to Route Service failed")
	})

	t.Run("test error from open store", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		_, err = New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store"),
			},
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			ServiceEndpointValue: "endpoint",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})

	t.Run("test error from open protocol state store", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		_, err = New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open protocol state store"),
			},
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			ServiceEndpointValue: "endpoint",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open protocol state store")
	})
}

func TestClient_CreateInvitation(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
		require.NoError(t, err)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})

		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation("agent")
		require.NoError(t, err)
		require.NotNil(t, inviteReq)
		require.NotEmpty(t, inviteReq.Label)
		require.NotEmpty(t, inviteReq.ID)
		require.Nil(t, inviteReq.RoutingKeys)
		require.Equal(t, "endpoint", inviteReq.ServiceEndpoint)
	})

	t.Run("test success with DIDCommV2 media profile", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		store := mockstore.NewMockStoreProvider()
		km := newKMS(t, store)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:               km,
			ServiceEndpointValue:   "endpoint",
			KeyAgreementTypeValue:  kms.NISTP521ECDHKWType,
			MediaTypeProfilesValue: []string{transport.MediaTypeDIDCommV2Profile},
		})

		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation("agent")
		require.NoError(t, err)
		require.NotNil(t, inviteReq)
		require.NotEmpty(t, inviteReq.Label)
		require.NotEmpty(t, inviteReq.ID)
		require.Nil(t, inviteReq.RoutingKeys)
		require.Equal(t, "endpoint", inviteReq.ServiceEndpoint)
	})

	t.Run("test success with DIDCommV2 media profile and KeyType option", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		store := mockstore.NewMockStoreProvider()
		km := newKMS(t, store)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:               km,
			ServiceEndpointValue:   "endpoint",
			KeyAgreementTypeValue:  kms.NISTP521ECDHKWType,
			MediaTypeProfilesValue: []string{transport.MediaTypeDIDCommV2Profile},
		})

		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation("agent", WithKeyType(kms.X25519ECDHKWType))
		require.NoError(t, err)
		require.NotNil(t, inviteReq)
		require.NotEmpty(t, inviteReq.Label)
		require.NotEmpty(t, inviteReq.ID)
		require.Nil(t, inviteReq.RoutingKeys)
		x25519DIDKeyPrefix := "did:key:z6L"
		require.Equal(t, x25519DIDKeyPrefix, inviteReq.RecipientKeys[0][:len(x25519DIDKeyPrefix)])
		require.Equal(t, "endpoint", inviteReq.ServiceEndpoint)
	})

	t.Run("test failure with DIDCommV2 media profile with empty kms key for calling "+
		"kmsdidkey.BuildDIDKeyByKeyType()", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:               &mockkms.KeyManager{},
			ServiceEndpointValue:   "endpoint",
			KeyAgreementTypeValue:  kms.NISTP521ECDHKWType,
			MediaTypeProfilesValue: []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		_, err = c.CreateInvitation("agent")
		require.EqualError(t, err, "createInvitation: failed to build did:key by key type: buildDIDkeyByKMSKeyType"+
			" failed to unmarshal key type NISTP521ECDHKW: unexpected end of JSON input")
	})

	t.Run("test error from createSigningKey", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue: &mockkms.KeyManager{CrAndExportPubKeyErr: fmt.Errorf("createKeyErr")},
		})
		require.NoError(t, err)
		_, err = c.CreateInvitation("agent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "createKeyErr")
	})

	t.Run("test error from save record", func(t *testing.T) {
		store := &mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrPut: fmt.Errorf("store error"),
		}

		svc, err := didexchange.New(&mockprotocol.MockProvider{
			StoreProvider: mockstore.NewCustomMockStoreProvider(store),
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewCustomMockStoreProvider(store),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue: &mockkms.KeyManager{},
		})
		require.NoError(t, err)
		_, err = c.CreateInvitation("agent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save invitation")
	})

	t.Run("test success with router registered", func(t *testing.T) {
		endpoint := "http://router.example.com"
		routingKeys := []string{"abc", "xyz"}

		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
		require.NoError(t, err)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination: &mockroute.MockMediatorSvc{
					Connections:    []string{"xyz"},
					RoutingKeys:    routingKeys,
					RouterEndpoint: endpoint,
				},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		inviteReq, err := c.CreateInvitation("agent", WithRouterConnectionID("xyz"))
		require.NoError(t, err)
		require.NotNil(t, inviteReq)
		require.NotEmpty(t, inviteReq.Label)
		require.NotEmpty(t, inviteReq.ID)
		require.Equal(t, endpoint, inviteReq.ServiceEndpoint)
		require.Equal(t, routingKeys, inviteReq.RoutingKeys)
	})

	t.Run("test create invitation with router config error", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
		require.NoError(t, err)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination: &mockroute.MockMediatorSvc{
					Connections: []string{"xyz"},
					ConfigErr:   errors.New("router config error"),
				},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		inviteReq, err := c.CreateInvitation("agent", WithRouterConnectionID("xyz"))
		require.EqualError(t, err, "createInvitation: getRouterConfig: fetch router config: router config error")
		require.Nil(t, inviteReq)
	})

	t.Run("test create invitation with adding key to router error", func(t *testing.T) {
		endpoint := "http://router.example.com"
		routingKeys := []string{"abc", "xyz"}

		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
		require.NoError(t, err)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination: &mockroute.MockMediatorSvc{
					Connections:    []string{"xyz"},
					RoutingKeys:    routingKeys,
					RouterEndpoint: endpoint,
					AddKeyErr:      errors.New("failed to add key to the router"),
				},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		inviteReq, err := c.CreateInvitation("agent", WithRouterConnectionID("xyz"))
		require.EqualError(t, err, "createInvitation: AddKeyToRouter: addKey: failed to add key to the router")
		require.Nil(t, inviteReq)
	})
}

func TestClient_CreateInvitationWithDID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
		require.NoError(t, err)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
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
		store := &mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrPut: fmt.Errorf("store error"),
		}

		svc, err := didexchange.New(&mockprotocol.MockProvider{
			StoreProvider: mockstore.NewCustomMockStoreProvider(store),
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewCustomMockStoreProvider(store),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue: &mockkms.KeyManager{},
		})
		require.NoError(t, err)

		_, err = c.CreateInvitationWithDID("agent", "did:sidetree:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save invitation")
	})
}

func TestClient_QueryConnectionByID(t *testing.T) {
	const (
		connID   = "id1"
		threadID = "thid1"
	)

	ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
	require.NoError(t, err)

	t.Run("test success", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		connRec := &connection.Record{ConnectionID: connID, ThreadID: threadID, State: "complete"}

		require.NoError(t, err)
		require.NoError(t, c.connectionStore.SaveConnectionRecord(connRec))
		result, err := c.GetConnection(connID)
		require.NoError(t, err)
		require.Equal(t, "complete", result.State)
		require.Equal(t, "id1", result.ConnectionID)
	})

	t.Run("test error", func(t *testing.T) {
		const errMsg = "query connection error"
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		store := &mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrGet: fmt.Errorf(errMsg),
		}

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewCustomMockStoreProvider(store),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		connRec := &connection.Record{ConnectionID: connID, ThreadID: threadID, State: "complete"}

		require.NoError(t, err)
		require.NoError(t, c.connectionStore.SaveConnectionRecord(connRec))
		_, err = c.GetConnection(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})

	t.Run("test data not found", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		result, err := c.GetConnection(connID)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrConnectionNotFound))
		require.Nil(t, result)
	})
}

func TestClient_GetConnection(t *testing.T) {
	connID := "id1"
	threadID := "thid1"

	t.Run("test failure", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)
		s := &mockstore.MockStore{Store: make(map[string]mockstore.DBEntry), ErrGet: ErrConnectionNotFound}
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		connRec := &connection.Record{ConnectionID: connID, ThreadID: threadID, State: "complete"}
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
	svc, err := didexchange.New(&mockprotocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, svc)

	// create client
	c, err := New(&mockprovider.Provider{
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: svc,
			mediator.Coordination:   &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)

	// not found
	result, err := c.GetConnectionAtState("id1", "complete")
	require.Equal(t, err.Error(), ErrConnectionNotFound.Error())
	require.Nil(t, result)
}

func TestClient_CreateConnection(t *testing.T) {
	t.Run("test create connection - success", func(t *testing.T) {
		theirDID := newPeerDID(t)
		myDID := newPeerDID(t)
		threadID := uuid.New().String()
		parentThreadID := uuid.New().String()
		label := uuid.New().String()
		invitationID := uuid.New().String()
		invitationDID := newPeerDID(t).ID
		implicit := true
		storageProvider := &mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
		}
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: storageProvider.ProtocolStateStorageProvider(),
			StorageProviderValue:              storageProvider.StorageProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{
					CreateConnRecordFunc: func(r *connection.Record, td *did.Doc) error {
						recorder, err := connection.NewRecorder(storageProvider)
						require.NoError(t, err)
						err = recorder.SaveConnectionRecord(r)
						require.NoError(t, err)

						return nil
					},
				},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		id, err := c.CreateConnection(myDID.ID, theirDID,
			WithTheirLabel(label), WithThreadID(threadID), WithParentThreadID(parentThreadID),
			WithInvitationID(invitationID), WithInvitationDID(invitationDID), WithImplicit(implicit))
		require.NoError(t, err)

		conn, err := c.GetConnection(id)
		require.NoError(t, err)
		require.Equal(t, connection.StateNameCompleted, conn.State)
		require.Equal(t, threadID, conn.ThreadID)
		require.Equal(t, parentThreadID, conn.ParentThreadID)
		require.Equal(t, label, conn.TheirLabel)
		require.Equal(t, theirDID.ID, conn.TheirDID)
		require.Equal(t, myDID.ID, conn.MyDID)
		require.Equal(t, invitationID, conn.InvitationID)
		require.Equal(t, invitationDID, conn.InvitationDID)
		require.Equal(t, theirDID.Service[0].ServiceEndpoint, conn.ServiceEndPoint)
		require.Equal(t, implicit, conn.Implicit)
	})

	t.Run("test create connection - error", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{
					CreateConnRecordFunc: func(*connection.Record, *did.Doc) error {
						return errors.New("save connection")
					},
				},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		id, err := c.CreateConnection(newPeerDID(t).ID, newPeerDID(t))
		require.EqualError(t, err, "createConnection: err: save connection")
		require.Empty(t, id)
	})

	t.Run("test create connection - error from CreateDestination", func(t *testing.T) {
		theirDID := newPeerDID(t)
		myDID := newPeerDID(t)
		threadID := uuid.New().String()
		parentThreadID := uuid.New().String()
		label := uuid.New().String()
		invitationID := uuid.New().String()
		invitationDID := newPeerDID(t).ID
		implicit := true
		storageProvider := &mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
		}
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: storageProvider.ProtocolStateStorageProvider(),
			StorageProviderValue:              storageProvider.StorageProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{
					CreateConnRecordFunc: func(r *connection.Record, td *did.Doc) error {
						recorder, err := connection.NewRecorder(storageProvider)
						require.NoError(t, err)
						err = recorder.SaveConnectionRecord(r)
						require.NoError(t, err)

						return nil
					},
				},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		// empty ServiceEndpoint to trigger CreateDestination error
		theirDID.Service[0].ServiceEndpoint = ""

		_, err = c.CreateConnection(myDID.ID, theirDID,
			WithTheirLabel(label), WithThreadID(threadID), WithParentThreadID(parentThreadID),
			WithInvitationID(invitationID), WithInvitationDID(invitationDID), WithImplicit(implicit))
		require.Contains(t, err.Error(), "createConnection: failed to create destination: "+
			"create destination: no service endpoint on didcomm service block in diddoc:")
	})
}

func TestClient_RemoveConnection(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		connID := "id1"
		threadID := "thid1"

		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mem.NewProvider(),
			StorageProviderValue:              mem.NewProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		connRec := &connection.Record{ConnectionID: connID, ThreadID: threadID, State: "complete"}

		require.NoError(t, err)
		require.NoError(t, c.connectionStore.SaveConnectionRecord(connRec))

		_, err = c.GetConnection(connID)
		require.NoError(t, err)

		err = c.RemoveConnection(connID)
		require.NoError(t, err)

		_, err = c.GetConnection(connID)
		require.Error(t, err)
		require.Equal(t, err.Error(), ErrConnectionNotFound.Error())
	})
	t.Run("test error data not found", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		err = c.RemoveConnection("sample-id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
	})
}

func TestClient_HandleInvitation(t *testing.T) {
	ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
	require.NoError(t, err)

	t.Run("test success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})

		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation("agent")
		require.NoError(t, err)

		connectionID, err := c.HandleInvitation(inviteReq)
		require.NoError(t, err)
		require.NotEmpty(t, connectionID)
	})

	t.Run("test error from handle msg", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{HandleFunc: func(msg service.DIDCommMsg) (string, error) {
					return "", fmt.Errorf("handle error")
				}},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},

			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation("agent")
		require.NoError(t, err)

		_, err = c.HandleInvitation(inviteReq)
		require.Error(t, err)
		require.Contains(t, err.Error(), "handle error")
	})
}

func TestClient_CreateImplicitInvitation(t *testing.T) {
	ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
	require.NoError(t, err)

	t.Run("test success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		connectionID, err := c.CreateImplicitInvitation("alice", "did:example:123")
		require.NoError(t, err)
		require.NotEmpty(t, connectionID)
	})

	t.Run("test error from service", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{
					ImplicitInvitationErr: errors.New("implicit error"),
				},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		connectionID, err := c.CreateImplicitInvitation("Alice", "did:example:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "implicit error")
		require.Empty(t, connectionID)
	})
}

func TestClient_CreateImplicitInvitationWithDID(t *testing.T) {
	inviter := &DIDInfo{Label: "alice", DID: "did:example:alice"}
	invitee := &DIDInfo{Label: "bob", DID: "did:example:bob"}

	ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
	require.NoError(t, err)

	t.Run("test success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		connectionID, err := c.CreateImplicitInvitationWithDID(inviter, invitee)
		require.NoError(t, err)
		require.NotEmpty(t, connectionID)
	})

	t.Run("test error from service", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{
					ImplicitInvitationErr: errors.New("implicit with DID error"),
				},
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		connectionID, err := c.CreateImplicitInvitationWithDID(inviter, invitee)
		require.Error(t, err)
		require.Contains(t, err.Error(), "implicit with DID error")
		require.Empty(t, connectionID)
	})

	t.Run("test missing required DID info", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			KMSValue:             &mockkms.KeyManager{CreateKeyValue: ed25519KH},
			ServiceEndpointValue: "endpoint",
		})
		require.NoError(t, err)

		connectionID, err := c.CreateImplicitInvitationWithDID(inviter, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing inviter and/or invitee public DID(s)")
		require.Empty(t, connectionID)

		connectionID, err = c.CreateImplicitInvitationWithDID(nil, invitee)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing inviter and/or invitee public DID(s)")
		require.Empty(t, connectionID)
	})
}

func TestClient_QueryConnectionsByParams(t *testing.T) { // nolint: gocyclo
	t.Run("test get all connections", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		storageProvider := mem.NewProvider()
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mem.NewProvider(),
			StorageProviderValue:              storageProvider,
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		didExchangeStore, err := storageProvider.OpenStore("didexchange")
		require.NoError(t, err)

		const count = 10
		const keyPrefix = "conn_"
		const state = "completed"
		for i := 0; i < count; i++ {
			val, e := json.Marshal(&connection.Record{
				ConnectionID: fmt.Sprint(i),
				State:        state,
			})
			require.NoError(t, e)
			require.NoError(t,
				didExchangeStore.Put(fmt.Sprintf("%sabc%d", keyPrefix, i), val, spi.Tag{Name: keyPrefix}))
		}

		results, err := c.QueryConnections(&QueryConnectionsParams{})
		require.NoError(t, err)
		require.Len(t, results, count)
		for _, result := range results {
			require.NotEmpty(t, result.ConnectionID)
		}
	})

	t.Run("test get connections with params", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		storageProvider := mem.NewProvider()
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mem.NewProvider(),
			StorageProviderValue:              storageProvider,
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		didExchangeStore, err := storageProvider.OpenStore("didexchange")
		require.NoError(t, err)

		const count = 10
		const countWithState = 5
		const keyPrefix = "conn_"
		const state = "completed"
		const myDID = "my_did"
		const theirDID = "their_did"
		for i := 0; i < count; i++ {
			var queryState string
			if i < countWithState {
				queryState = state
			}

			val, e := json.Marshal(&connection.Record{
				ConnectionID:   fmt.Sprint(i),
				InvitationID:   fmt.Sprintf("inv-%d", i),
				ParentThreadID: fmt.Sprintf("ptid-%d", i),
				State:          queryState,
				MyDID:          myDID + strconv.Itoa(i),
				TheirDID:       theirDID + strconv.Itoa(i),
			})
			require.NoError(t, e)
			require.NoError(t,
				didExchangeStore.Put(fmt.Sprintf("%sabc%d", keyPrefix, i), val, spi.Tag{Name: keyPrefix}))
		}

		results, err := c.QueryConnections(&QueryConnectionsParams{})
		require.NoError(t, err)
		require.Len(t, results, count)
		for _, result := range results {
			require.NotEmpty(t, result.ConnectionID)
		}

		results, err = c.QueryConnections(&QueryConnectionsParams{State: state})
		require.NoError(t, err)
		require.Len(t, results, countWithState)
		for _, result := range results {
			require.NotEmpty(t, result.ConnectionID)
			require.Equal(t, result.State, state)
		}

		params := &QueryConnectionsParams{MyDID: myDID + strconv.Itoa(count-1)}
		results, err = c.QueryConnections(params)
		require.NoError(t, err)
		require.Len(t, results, 1)
		for _, result := range results {
			require.NotEmpty(t, result.ConnectionID)
			require.Equal(t, result.MyDID, params.MyDID)
		}

		params = &QueryConnectionsParams{TheirDID: theirDID + strconv.Itoa(count-1)}
		results, err = c.QueryConnections(params)
		require.NoError(t, err)
		require.Len(t, results, 1)
		for _, result := range results {
			require.NotEmpty(t, result.ConnectionID)
			require.Equal(t, result.TheirDID, params.TheirDID)
		}

		params = &QueryConnectionsParams{
			MyDID:    myDID + strconv.Itoa(count-1),
			TheirDID: theirDID + strconv.Itoa(count-1),
		}
		results, err = c.QueryConnections(params)
		require.NoError(t, err)
		require.Len(t, results, 1)
		for _, result := range results {
			require.NotEmpty(t, result.ConnectionID)
			require.Equal(t, result.MyDID, params.MyDID)
			require.Equal(t, result.TheirDID, params.TheirDID)
		}

		params = &QueryConnectionsParams{
			InvitationID: fmt.Sprintf("inv-%d", count-1),
		}
		results, err = c.QueryConnections(params)
		require.NoError(t, err)
		require.Len(t, results, 1)
		for _, result := range results {
			require.NotEmpty(t, result.ConnectionID)
			require.Equal(t, result.InvitationID, params.InvitationID)
		}

		params = &QueryConnectionsParams{
			ParentThreadID: fmt.Sprintf("ptid-%d", count-1),
		}
		results, err = c.QueryConnections(params)
		require.NoError(t, err)
		require.Len(t, results, 1)
		for _, result := range results {
			require.NotEmpty(t, result.ConnectionID)
			require.Equal(t, result.ParentThreadID, params.ParentThreadID)
		}
	})

	t.Run("test get connections error", func(t *testing.T) {
		svc, err := didexchange.New(&mockprotocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)
		const keyPrefix = "conn_"

		storageProvider := mem.NewProvider()
		c, err := New(&mockprovider.Provider{
			ProtocolStateStorageProviderValue: mem.NewProvider(),
			StorageProviderValue:              storageProvider,
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: svc,
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		didExchangeStore, err := storageProvider.OpenStore("didexchange")
		require.NoError(t, err)

		require.NoError(t,
			didExchangeStore.Put(fmt.Sprintf("%sabc", keyPrefix), []byte("----"), spi.Tag{Name: keyPrefix}))

		results, err := c.QueryConnections(&QueryConnectionsParams{})
		require.Error(t, err)
		require.Empty(t, results)
	})
}

func TestServiceEvents(t *testing.T) {
	protocolStateStore := mockstore.NewMockStoreProvider()
	store := mockstore.NewMockStoreProvider()
	km := newKMS(t, store)
	didExSvc, err := didexchange.New(&mockprotocol.MockProvider{
		ProtocolStateStoreProvider: protocolStateStore,
		StoreProvider:              store,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		CustomKMS:             km,
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	})
	require.NoError(t, err)

	// create the client
	c, err := New(&mockprovider.Provider{
		ProtocolStateStorageProviderValue: protocolStateStore,
		StorageProviderValue:              store,
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: didExSvc,
			mediator.Coordination:   &mockroute.MockMediatorSvc{},
		},
		KMSValue:              km,
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	})
	require.NoError(t, err)
	require.NotNil(t, c)

	// register action event channel
	aCh := make(chan service.DIDCommAction, 10)
	err = c.RegisterActionEvent(aCh)
	require.NoError(t, err)

	go func() {
		service.AutoExecuteActionEvent(aCh)
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
	doc, err := (&mockvdr.MockVDRegistry{}).Create("test", nil)
	require.NoError(t, err)

	invitation, err := c.CreateInvitation("alice")
	require.NoError(t, err)

	request, err := json.Marshal(
		&didexchange.Request{
			Type:  didexchange.RequestMsgType,
			ID:    id,
			Label: "test",
			Thread: &decorator.Thread{
				PID: invitation.ID,
			},
			DID:       doc.DIDDocument.ID,
			DocAttach: unsignedDocAttach(t, doc.DIDDocument),
		},
	)
	require.NoError(t, err)

	msg, err := service.ParseDIDCommMsgMap(request)
	require.NoError(t, err)
	_, err = didExSvc.HandleInbound(msg, service.EmptyDIDCommContext())
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

func TestAcceptExchangeRequest(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	km := newKMS(t, store)
	didExSvc, err := didexchange.New(&mockprotocol.MockProvider{
		StoreProvider: store,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		CustomKMS:             km,
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	})
	require.NoError(t, err)

	// create the client
	c, err := New(&mockprovider.Provider{
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:              store,
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: didExSvc,
			mediator.Coordination:   &mockroute.MockMediatorSvc{},
		},
		KMSValue:              km,
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	},
	)
	require.NoError(t, err)
	require.NotNil(t, c)

	// register action event channel
	aCh := make(chan service.DIDCommAction, 10)
	err = c.RegisterActionEvent(aCh)
	require.NoError(t, err)

	go func() {
		for e := range aCh {
			prop, ok := e.Properties.(Event)
			if !ok {
				require.Fail(t, "Failed to cast the event properties to service.Event")
			}

			require.NoError(t, c.AcceptExchangeRequest(prop.ConnectionID(), "", ""))
		}
	}()

	// register message event channel
	mCh := make(chan service.StateMsg, 10)
	err = c.RegisterMsgEvent(mCh)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for e := range mCh {
			if e.Type == service.PostState && e.StateID == "responded" {
				close(done)
			}
		}
	}()

	invitation, err := c.CreateInvitation("alice")
	require.NoError(t, err)
	// send connection request message
	id := "valid-thread-id"
	doc, err := (&mockvdr.MockVDRegistry{}).Create("test", nil)
	require.NoError(t, err)

	request, err := json.Marshal(
		&didexchange.Request{
			Type:  didexchange.RequestMsgType,
			ID:    id,
			Label: "test",
			Thread: &decorator.Thread{
				PID: invitation.ID,
			},
			DocAttach: unsignedDocAttach(t, doc.DIDDocument),
			DID:       doc.DIDDocument.ID,
		},
	)
	require.NoError(t, err)

	msg, err := service.ParseDIDCommMsgMap(request)
	require.NoError(t, err)
	_, err = didExSvc.HandleInbound(msg, service.EmptyDIDCommContext())
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated due to timeout")
	}

	err = c.AcceptExchangeRequest("invalid-id", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "did exchange client - accept exchange request:")
}

func TestAcceptInvitation(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	km := newKMS(t, store)
	didExSvc, err := didexchange.New(&mockprotocol.MockProvider{
		StoreProvider: store,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		CustomKMS:             km,
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	})
	require.NoError(t, err)

	// create the client
	c, err := New(&mockprovider.Provider{
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:              store,
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: didExSvc,
			mediator.Coordination:   &mockroute.MockMediatorSvc{},
		},
		KMSValue:              km,
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	})
	require.NoError(t, err)
	require.NotNil(t, c)

	t.Run("accept invitation - success", func(t *testing.T) {
		// register action event channel
		aCh := make(chan service.DIDCommAction, 10)
		err = c.RegisterActionEvent(aCh)
		require.NoError(t, err)

		go func() {
			for e := range aCh {
				_, ok := e.Properties.(Event)
				require.True(t, ok, "Failed to cast the event properties to service.Event")

				// ignore action event
			}
		}()

		// register message event channel
		mCh := make(chan service.StateMsg, 10)
		err = c.RegisterMsgEvent(mCh)
		require.NoError(t, err)

		done := make(chan struct{})

		go func() {
			for e := range mCh {
				prop, ok := e.Properties.(Event)
				if !ok {
					require.Fail(t, "Failed to cast the event properties to service.Event")
				}

				if e.Type == service.PostState && e.StateID == "invited" {
					require.NoError(t, c.AcceptInvitation(prop.ConnectionID(), "", ""))
				}

				if e.Type == service.PostState && e.StateID == "requested" {
					close(done)
				}
			}
		}()

		_, pubKey, e := km.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, e)

		// send connection invitation message
		invitation, jsonErr := json.Marshal(
			&didexchange.Invitation{
				Type:          InvitationMsgType,
				ID:            "abc",
				Label:         "test",
				RecipientKeys: []string{string(pubKey)},
			},
		)
		require.NoError(t, jsonErr)

		msg, svcErr := service.ParseDIDCommMsgMap(invitation)
		require.NoError(t, svcErr)
		_, err = didExSvc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("accept invitation - error", func(t *testing.T) {
		err = c.AcceptInvitation("invalid-id", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did exchange client - accept exchange invitation")
	})
}

func newPeerDID(t *testing.T) *did.Doc {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	d, err := ctx.VDRegistry().Create(
		peer.DIDMethod, &did.Doc{Service: []did.Service{{
			Type:            "did-communication",
			ServiceEndpoint: "http://agent.example.com/didcomm",
		}}, VerificationMethod: []did.VerificationMethod{getSigningKey()}})
	require.NoError(t, err)

	return d.DIDDocument
}

func getSigningKey() did.VerificationMethod {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return did.VerificationMethod{Value: pub[:], Type: "Ed25519VerificationKey2018"}
}

func newKMS(t *testing.T, store spi.Provider) kms.KeyManager {
	t.Helper()

	kmsProv := &mockprotocol.MockProvider{
		StoreProvider: store,
		CustomLock:    &noop.NoLock{},
	}

	customKMS, err := localkms.New("local-lock://primary/test/", kmsProv)
	require.NoError(t, err)

	return customKMS
}

func unsignedDocAttach(t *testing.T, doc *did.Doc) *decorator.Attachment {
	t.Helper()

	docBytes, err := doc.JSONBytes()
	require.NoError(t, err)

	att := &decorator.Attachment{
		Data: decorator.AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(docBytes),
		},
	}

	return att
}
