/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	commonmodel "github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	testMethod    = "peer"
	threadIDValue = "xyz"
)

type event interface {
	// connection ID
	ConnectionID() string

	// invitation ID
	InvitationID() string
}

func TestService_Name(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		prov, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.Equal(t, LegacyConnection, prov.Name())
	})
}

func TestServiceNew(t *testing.T) {
	t.Run("test error from open store", func(t *testing.T) {
		_, err := New(
			&protocol.MockProvider{StoreProvider: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store"),
			}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})

	t.Run("test error from open protocol state store", func(t *testing.T) {
		_, err := New(
			&protocol.MockProvider{ProtocolStateStoreProvider: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open protocol state store"),
			}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open protocol state store")
	})

	t.Run("test service new error - no route service found", func(t *testing.T) {
		_, err := New(&protocol.MockProvider{ServiceErr: errors.New("service not found")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "service not found")
	})

	t.Run("test service new error - casting to route service failed", func(t *testing.T) {
		_, err := New(&protocol.MockProvider{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to Route Service failed")
	})
}

func TestService_Initialize(t *testing.T) {
	t.Run("success: already initialized", func(t *testing.T) {
		prov := &protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		}

		svc, err := New(prov)
		require.NoError(t, err)

		require.NoError(t, svc.Initialize(prov))
	})

	t.Run("fail: provider of wrong type", func(t *testing.T) {
		prov := "this is not a provider"

		svc := Service{}

		err := svc.Initialize(prov)

		require.Error(t, err)
		require.Contains(t, err.Error(), "expected provider of type")
	})
}

// connection flow with role Inviter.
func TestService_Handle_Inviter(t *testing.T) {
	mockStore := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}
	storeProv := mockstorage.NewCustomMockStoreProvider(mockStore)
	k := newKMS(t, storeProv)
	prov := &protocol.MockProvider{
		StoreProvider: storeProv,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		CustomKMS:             k,
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	}

	ctx := &context{
		outboundDispatcher: prov.OutboundDispatcher(),
		crypto:             &tinkcrypto.Crypto{},
		kms:                k,
		keyType:            kms.ED25519Type,
		keyAgreementType:   kms.X25519ECDHKWType,
	}

	_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: createDIDDocWithKey(pubKey)}

	connRec, err := connection.NewRecorder(prov)
	require.NoError(t, err)
	require.NotNil(t, connRec)

	ctx.connectionRecorder = connRec

	doc, err := ctx.vdRegistry.Create(testMethod, nil)
	require.NoError(t, err)

	s, err := New(prov)
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = s.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	statusCh := make(chan service.StateMsg, 10)
	err = s.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	completedFlag := make(chan struct{})
	respondedFlag := make(chan struct{})

	go msgEventListener(t, statusCh, respondedFlag, completedFlag)

	go func() { service.AutoExecuteActionEvent(actionCh) }()

	invitation := &Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{base58.Encode(pubKey)},
		ServiceEndpoint: "http://alice.agent.example.com:8081",
	}

	err = ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
	require.NoError(t, err)

	thid := randomString()

	// Invitation was previously sent by Alice to Bob.
	// Bob now sends a connection Request
	payloadBytes, err := json.Marshal(
		&Request{
			Type:  RequestMsgType,
			ID:    thid,
			Label: "Bob",
			Thread: &decorator.Thread{
				PID: invitation.ID,
			},
			Connection: &Connection{
				DID:    doc.DIDDocument.ID,
				DIDDoc: doc.DIDDocument,
			},
		})
	require.NoError(t, err)
	msg, err := service.ParseDIDCommMsgMap(payloadBytes)
	require.NoError(t, err)
	_, err = s.HandleInbound(msg, service.NewDIDCommContext(doc.DIDDocument.ID, "", nil))
	require.NoError(t, err)

	select {
	case <-respondedFlag:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event responded")
	}
	// Alice automatically sends connection Response to Bob
	// Bob replies with an ACK
	payloadBytes, err = json.Marshal(
		&model.Ack{
			Type:   AckMsgType,
			ID:     randomString(),
			Status: "OK",
			Thread: &decorator.Thread{ID: thid},
		})
	require.NoError(t, err)

	didMsg, err := service.ParseDIDCommMsgMap(payloadBytes)
	require.NoError(t, err)

	_, err = s.HandleInbound(didMsg, service.NewDIDCommContext(doc.DIDDocument.ID, "", nil))
	require.NoError(t, err)

	select {
	case <-completedFlag:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event complete")
	}

	validateState(t, s, thid, findNamespace(AckMsgType), (&completed{}).Name())
}

func msgEventListener(t *testing.T, statusCh chan service.StateMsg, respondedFlag, completedFlag chan struct{}) {
	for e := range statusCh {
		require.Equal(t, LegacyConnection, e.ProtocolName)

		prop, ok := e.Properties.(event)
		if !ok {
			require.Fail(t, "Failed to cast the event properties to service.Event")
		}
		// Get the connectionID when it's created
		if e.Type == service.PreState {
			if e.StateID == "requested" {
				require.NotNil(t, prop.ConnectionID())
				require.NotNil(t, prop.InvitationID())
			}
		}

		if e.Type == service.PostState {
			// receive the events
			if e.StateID == "completed" {
				// validate connectionID received during state transition with original connectionID
				require.NotNil(t, prop.ConnectionID())
				require.NotNil(t, prop.InvitationID())
				close(completedFlag)
			}

			if e.StateID == "responded" {
				// validate connectionID received during state transition with original connectionID
				require.NotNil(t, prop.ConnectionID())
				require.NotNil(t, prop.InvitationID())
				close(respondedFlag)
			}
		}
	}
}

type kmsProvider struct {
	store             kms.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kms.Store {
	return k.store
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

func newKMS(t *testing.T, store storage.Provider) kms.KeyManager {
	t.Helper()

	kmsStore, err := kms.NewAriesProviderWrapper(store)
	require.NoError(t, err)

	kmsProv := &kmsProvider{
		store:             kmsStore,
		secretLockService: &noop.NoLock{},
	}

	customKMS, err := localkms.New("local-lock://primary/test/", kmsProv)
	require.NoError(t, err)

	return customKMS
}

// connection flow with role Invitee.
func TestService_Handle_Invitee(t *testing.T) {
	protocolStateStore := mockstorage.NewMockStoreProvider()
	store := mockstorage.NewMockStoreProvider()
	k := newKMS(t, store)
	prov := &protocol.MockProvider{
		StoreProvider:              store,
		ProtocolStateStoreProvider: protocolStateStore,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		CustomKMS:             k,
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	}

	mtp := transport.MediaTypeRFC0019EncryptedEnvelope

	ctx := &context{
		outboundDispatcher: prov.OutboundDispatcher(),
		crypto:             &tinkcrypto.Crypto{},
		kms:                k,
		keyType:            kms.ED25519Type,
		keyAgreementType:   kms.X25519ECDHKWType,
		mediaTypeProfiles:  []string{mtp},
	}

	_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: createDIDDocWithKey(verPubKey)}

	connRec, err := connection.NewRecorder(prov)
	require.NoError(t, err)
	require.NotNil(t, connRec)

	ctx.connectionRecorder = connRec

	doc, err := ctx.vdRegistry.Create(testMethod, nil)
	require.NoError(t, err)

	s, err := New(prov)
	require.NoError(t, err)

	s.ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: doc.DIDDocument}
	actionCh := make(chan service.DIDCommAction, 10)
	err = s.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	statusCh := make(chan service.StateMsg, 10)
	err = s.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	requestedCh := make(chan string)
	completedCh := make(chan struct{})

	go handleMessagesInvitee(statusCh, requestedCh, completedCh)

	go func() { service.AutoExecuteActionEvent(actionCh) }()

	invitation := &Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{base58.Encode(verPubKey)},
		ServiceEndpoint: "http://alice.agent.example.com:8081",
	}

	err = ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
	require.NoError(t, err)
	// Alice receives an invitation from Bob
	payloadBytes, err := json.Marshal(invitation)
	require.NoError(t, err)

	didMsg, err := service.ParseDIDCommMsgMap(payloadBytes)
	require.NoError(t, err)

	_, err = s.HandleInbound(didMsg, service.EmptyDIDCommContext())
	require.NoError(t, err)

	var connID string
	select {
	case connID = <-requestedCh:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event requested")
	}

	// Alice automatically sends a Request to Bob and is now in REQUESTED state.
	connRecord, err := s.connectionRecorder.GetConnectionRecord(connID)
	require.NoError(t, err)
	require.Equal(t, (&requested{}).Name(), connRecord.State)
	require.Equal(t, invitation.ID, connRecord.InvitationID)
	require.Equal(t, invitation.RecipientKeys, connRecord.RecipientKeys)
	uri, err := connRecord.ServiceEndPoint.URI()
	require.NoError(t, err)
	require.Equal(t, invitation.ServiceEndpoint, uri)

	connectionSignature, err := ctx.prepareConnectionSignature(doc.DIDDocument, invitation.RecipientKeys[0])
	require.NoError(t, err)

	// Bob replies with a Response
	payloadBytes, err = json.Marshal(
		&Response{
			Type: ResponseMsgType,
			ID:   randomString(),
			Thread: &decorator.Thread{
				ID: connRecord.ThreadID,
			},
			ConnectionSignature: connectionSignature,
			PleaseAck: &PleaseAck{
				On: []string{PlsAckOnReceipt},
			},
		},
	)
	require.NoError(t, err)

	didMsg, err = service.ParseDIDCommMsgMap(payloadBytes)
	require.NoError(t, err)

	_, err = s.HandleInbound(didMsg, service.EmptyDIDCommContext())
	require.NoError(t, err)

	// Alice automatically sends an ACK to Bob
	// Alice must now be in COMPLETED state
	select {
	case <-completedCh:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event complete")
	}

	validateState(t, s, connRecord.ThreadID, findNamespace(ResponseMsgType), (&completed{}).Name())
}

func handleMessagesInvitee(statusCh chan service.StateMsg, requestedCh chan string, completedCh chan struct{}) {
	for e := range statusCh {
		if e.Type == service.PostState {
			// receive the events
			if e.StateID == StateIDCompleted {
				close(completedCh)
			} else if e.StateID == StateIDRequested {
				prop, ok := e.Properties.(event)
				if !ok {
					panic("Failed to cast the event properties to service.Event")
				}

				requestedCh <- prop.ConnectionID()
			}
		}
	}
}

func TestService_Handle_EdgeCases(t *testing.T) {
	t.Run("handleInbound - must not transition to same state", func(t *testing.T) {
		s, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		err = s.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)

		response, err := json.Marshal(
			&Response{
				Type:   ResponseMsgType,
				ID:     randomString(),
				Thread: &decorator.Thread{ID: randomString()},
			},
		)
		require.NoError(t, err)

		didMsg, err := service.ParseDIDCommMsgMap(response)
		require.NoError(t, err)

		_, err = s.HandleInbound(didMsg, service.EmptyDIDCommContext())
		require.Error(t, err)
		require.Contains(t, err.Error(), "handle inbound - next state : invalid state transition: "+
			"null -> responded")
	})

	t.Run("handleInbound - connection record error", func(t *testing.T) {
		protocolStateStore := &mockstorage.MockStore{
			Store:  make(map[string]mockstorage.DBEntry),
			ErrPut: errors.New("db error"),
		}
		prov := &protocol.MockProvider{
			ProtocolStateStoreProvider: mockstorage.NewCustomMockStoreProvider(protocolStateStore),
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		}
		svc, err := New(prov)
		require.NoError(t, err)

		err = svc.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)

		svc.connectionRecorder, err = connection.NewRecorder(prov)
		require.NotNil(t, svc.connectionRecorder)
		require.NoError(t, err)

		_, err = svc.HandleInbound(
			generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString(), randomString()),
			service.EmptyDIDCommContext())
		require.Error(t, err)
		require.Contains(t, err.Error(), "save connection record")
	})

	t.Run("handleInbound - no error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		err = svc.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)

		protocolStateStore := &mockStore{
			get: func(s string) (bytes []byte, e error) {
				return nil, storage.ErrDataNotFound
			},
			put: func(s string, bytes []byte, tags ...storage.Tag) error {
				if strings.Contains(s, "didex-event-") {
					return errors.New("db error")
				}

				return nil
			},
		}

		svc.connectionRecorder, err = connection.NewRecorder(&protocol.MockProvider{
			ProtocolStateStoreProvider: mockstorage.NewCustomMockStoreProvider(protocolStateStore),
		})
		require.NotNil(t, svc.connectionRecorder)
		require.NoError(t, err)

		requestBytes, err := json.Marshal(&Request{
			Type: RequestMsgType,
			ID:   generateRandomID(),
			Connection: &Connection{
				DID: "xyz",
			},
			Thread: &decorator.Thread{
				PID: randomString(),
			},
		})
		require.NoError(t, err)

		// send invite
		didMsg, err := service.ParseDIDCommMsgMap(requestBytes)
		require.NoError(t, err)

		_, err = svc.HandleInbound(didMsg, service.EmptyDIDCommContext())
		require.NoError(t, err)
	})
}

func TestService_Accept(t *testing.T) {
	s := &Service{}

	require.Equal(t, true, s.Accept("https://didcomm.org/connections/1.0/invitation"))
	require.Equal(t, true, s.Accept("https://didcomm.org/connections/1.0/request"))
	require.Equal(t, true, s.Accept("https://didcomm.org/connections/1.0/response"))
	require.Equal(t, true, s.Accept("https://didcomm.org/notification/1.0/ack"))
	require.Equal(t, false, s.Accept("unsupported msg type"))
}

func TestService_CurrentState(t *testing.T) {
	t.Run("null state if not found in store", func(t *testing.T) {
		connRec, err := connection.NewRecorder(&protocol.MockProvider{
			StoreProvider: mockstorage.NewCustomMockStoreProvider(&mockStore{
				get: func(string) ([]byte, error) { return nil, storage.ErrDataNotFound },
			}),
		})
		require.NotNil(t, connRec)
		require.NoError(t, err)

		svc := &Service{
			connectionRecorder: connRec,
		}
		thid, err := connection.CreateNamespaceKey(theirNSPrefix, "ignored")
		require.NoError(t, err)
		s, err := svc.currentState(thid)
		require.NoError(t, err)
		require.Equal(t, (&null{}).Name(), s.Name())
	})

	t.Run("returns state from store", func(t *testing.T) {
		expected := &requested{}
		connRecord, err := json.Marshal(&connection.Record{State: expected.Name()})
		require.NoError(t, err)

		connRec, err := connection.NewRecorder(&protocol.MockProvider{
			ProtocolStateStoreProvider: mockstorage.NewCustomMockStoreProvider(&mockStore{
				get: func(string) ([]byte, error) { return connRecord, nil },
			}),
		})
		require.NotNil(t, connRec)
		require.NoError(t, err)

		svc := &Service{
			connectionRecorder: connRec,
		}
		thid, err := connection.CreateNamespaceKey(theirNSPrefix, "ignored")
		require.NoError(t, err)
		actual, err := svc.currentState(thid)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})

	t.Run("forwards generic error from store", func(t *testing.T) {
		connRec, err := connection.NewRecorder(&protocol.MockProvider{
			ProtocolStateStoreProvider: mockstorage.NewCustomMockStoreProvider(&mockStore{
				get: func(string) ([]byte, error) {
					return nil, errors.New("test")
				},
			}),
		})
		require.NotNil(t, connRec)
		require.NoError(t, err)

		svc := &Service{connectionRecorder: connRec}
		thid, err := connection.CreateNamespaceKey(theirNSPrefix, "ignored")
		require.NoError(t, err)
		_, err = svc.currentState(thid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot fetch state from store")
	})
}

func TestService_Update(t *testing.T) {
	s := &requested{}
	data := make(map[string][]byte)
	connRecord := &connection.Record{
		ThreadID: "123", ConnectionID: "123456", State: s.Name(),
		Namespace: findNamespace(RequestMsgType),
	}
	bytes, err := json.Marshal(connRecord)
	require.NoError(t, err)

	connRec, err := connection.NewRecorder(&protocol.MockProvider{
		StoreProvider: mockstorage.NewCustomMockStoreProvider(&mockStore{
			put: func(k string, v []byte, tags ...storage.Tag) error {
				data[k] = bytes
				return nil
			},
			get: func(k string) ([]byte, error) {
				return bytes, nil
			},
		}),
	})
	require.NotNil(t, connRec)
	require.NoError(t, err)

	svc := &Service{connectionRecorder: connRec}

	require.NoError(t, svc.update(RequestMsgType, connRecord))

	cr := &connection.Record{}
	err = json.Unmarshal(bytes, cr)
	require.NoError(t, err)
	require.Equal(t, cr, connRecord)
}

func TestCreateConnection(t *testing.T) {
	store := mockstorage.NewMockStoreProvider()
	k := newKMS(t, store)

	t.Run("create connection", func(t *testing.T) {
		theirDID := newPeerDID(t, k)
		record := &connection.Record{
			ConnectionID:    uuid.New().String(),
			State:           StateIDCompleted,
			ThreadID:        uuid.New().String(),
			ParentThreadID:  uuid.New().String(),
			TheirLabel:      uuid.New().String(),
			TheirDID:        theirDID.ID,
			MyDID:           newPeerDID(t, k).ID,
			ServiceEndPoint: commonmodel.NewDIDCommV1Endpoint("http://example.com"),
			RecipientKeys:   []string{"testkeys"},
			InvitationID:    uuid.New().String(),
			Namespace:       myNSPrefix,
		}
		storedInVDR := false
		storageProvider := &mockprovider.Provider{
			StorageProviderValue:              mockstorage.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
		}
		provider := &mockprovider.Provider{
			KMSValue:                          &mockkms.KeyManager{},
			StorageProviderValue:              storageProvider.StorageProvider(),
			ProtocolStateStorageProviderValue: storageProvider.ProtocolStateStorageProvider(),
			VDRegistryValue: &mockvdr.MockVDRegistry{
				CreateFunc: func(method string, result *did.Doc, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					storedInVDR = true
					require.Equal(t, theirDID, result)

					return nil, nil
				},
			},
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			DIDConnectionStoreValue: &mockConnectionStore{},
		}
		s, err := New(provider)
		require.NoError(t, err)

		err = s.CreateConnection(record, theirDID)
		require.True(t, storedInVDR)
		require.NoError(t, err)

		connRec, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		result, err := connRec.GetConnectionRecord(record.ConnectionID)
		require.NoError(t, err)
		require.Equal(t, record, result)
	})

	t.Run("wraps vdr registry error", func(t *testing.T) {
		expected := errors.New("test")
		s, err := New(&mockprovider.Provider{
			KMSValue:                          &mockkms.KeyManager{},
			StorageProviderValue:              mockstorage.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
			VDRegistryValue: &mockvdr.MockVDRegistry{
				CreateFunc: func(s string, doc *did.Doc, option ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					return nil, expected
				},
			},
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		err = s.CreateConnection(&connection.Record{}, newPeerDID(t, k))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps connection store error", func(t *testing.T) {
		expected := errors.New("test")
		s, err := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{},
			StorageProviderValue: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{ErrPut: expected},
			},
			ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
			VDRegistryValue:                   &mockvdr.MockVDRegistry{},
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			DIDConnectionStoreValue: &mockConnectionStore{},
		})
		require.NoError(t, err)

		err = s.CreateConnection(&connection.Record{
			State: StateIDCompleted,
		}, newPeerDID(t, k))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps did.ConnectionStore.SaveDIDFromDoc error", func(t *testing.T) {
		expected := errors.New("test")
		s, err := New(&mockprovider.Provider{
			KMSValue:                          &mockkms.KeyManager{},
			KeyTypeValue:                      kms.ECDSAP384TypeIEEEP1363,
			KeyAgreementTypeValue:             kms.X25519ECDHKWType,
			StorageProviderValue:              mockstorage.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
			VDRegistryValue:                   &mockvdr.MockVDRegistry{},
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			DIDConnectionStoreValue: &mockConnectionStore{
				saveDIDFromDocErr: expected,
			},
		})
		require.NoError(t, err)

		err = s.CreateConnection(&connection.Record{
			State: StateIDCompleted,
		}, newPeerDID(t, k))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps did.ConnectionStore.SaveDIDByResolving error", func(t *testing.T) {
		expected := errors.New("test")
		s, err := New(&mockprovider.Provider{
			KMSValue:                          &mockkms.KeyManager{},
			KeyTypeValue:                      kms.ED25519Type,
			KeyAgreementTypeValue:             kms.X25519ECDHKWType,
			StorageProviderValue:              mockstorage.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
			VDRegistryValue:                   &mockvdr.MockVDRegistry{},
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			DIDConnectionStoreValue: &mockConnectionStore{
				saveDIDByResolvingErr: expected,
			},
		})
		require.NoError(t, err)

		err = s.CreateConnection(&connection.Record{
			State: StateIDCompleted,
		}, newPeerDID(t, k))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

type mockStore struct {
	put    func(string, []byte, ...storage.Tag) error
	get    func(string) ([]byte, error)
	delete func(string) error
}

// Put stores the key and the record.
func (m *mockStore) Put(k string, v []byte, tags ...storage.Tag) error {
	return m.put(k, v, tags...)
}

// Get fetches the record based on key.
func (m *mockStore) Get(k string) ([]byte, error) {
	return m.get(k)
}

func (m *mockStore) GetTags(key string) ([]storage.Tag, error) {
	panic("implement me")
}

func (m *mockStore) GetBulk(keys ...string) ([][]byte, error) {
	panic("implement me")
}

func (m *mockStore) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	panic("implement me")
}

// Delete the record based on key.
func (m *mockStore) Delete(k string) error {
	return m.delete(k)
}

func (m *mockStore) Batch(operations []storage.Operation) error {
	panic("implement me")
}

func (m *mockStore) Flush() error {
	panic("implement me")
}

func (m *mockStore) Close() error {
	panic("implement me")
}

func TestEventsSuccess(t *testing.T) {
	sp := mockstorage.NewMockStoreProvider()
	k := newKMS(t, sp)
	ctx := &context{
		kms:              k,
		keyType:          kms.ED25519Type,
		keyAgreementType: kms.X25519ECDHKWType,
	}

	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		CustomKMS:             k,
		KeyTypeValue:          ctx.keyType,
		KeyAgreementTypeValue: ctx.keyAgreementType,
	})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() { service.AutoExecuteActionEvent(actionCh) }()

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for e := range statusCh {
			if e.Type == service.PostState && e.StateID == StateIDRequested {
				done <- struct{}{}
			}
		}
	}()

	_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	id := randomString()
	invite, err := json.Marshal(
		&Invitation{
			Type:          InvitationMsgType,
			ID:            id,
			Label:         "test",
			RecipientKeys: []string{base58.Encode(pubKey)},
		},
	)
	require.NoError(t, err)

	// send invite
	didMsg, err := service.ParseDIDCommMsgMap(invite)
	require.NoError(t, err)

	_, err = svc.HandleInbound(didMsg, service.EmptyDIDCommContext())
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestContinueWithPublicDID(t *testing.T) {
	sp := mockstorage.NewMockStoreProvider()
	k := newKMS(t, sp)
	ctx := &context{
		kms:              k,
		keyType:          kms.ED25519Type,
		keyAgreementType: kms.X25519ECDHKWType,
	}
	didDoc := mockdiddoc.GetMockDIDDoc(t, false)
	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		KeyTypeValue:          ctx.keyType,
		KeyAgreementTypeValue: ctx.keyAgreementType,
	})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() { continueWithPublicDID(actionCh, didDoc.ID) }()

	_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	id := randomString()
	invite, err := json.Marshal(
		&Invitation{
			Type:          InvitationMsgType,
			ID:            id,
			Label:         "test",
			RecipientKeys: []string{base58.Encode(pubKey)},
		},
	)
	require.NoError(t, err)

	// send invite
	didMsg, err := service.ParseDIDCommMsgMap(invite)
	require.NoError(t, err)

	_, err = svc.HandleInbound(didMsg, service.EmptyDIDCommContext())
	require.NoError(t, err)
}

func continueWithPublicDID(ch chan service.DIDCommAction, pubDID string) {
	for msg := range ch {
		msg.Continue(&testOptions{publicDID: pubDID})
	}
}

type testOptions struct {
	publicDID         string
	label             string
	routerConnections []string
}

func (to *testOptions) PublicDID() string {
	return to.publicDID
}

func (to *testOptions) Label() string {
	return to.label
}

func (to *testOptions) RouterConnections() []string {
	return to.routerConnections
}

func TestEventsUserError(t *testing.T) {
	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for {
			select {
			case e := <-actionCh:
				e.Stop(errors.New("invalid id"))
			case e := <-statusCh:
				if e.Type == service.PostState {
					done <- struct{}{}
				}
			}
		}
	}()

	id := randomString()
	connRec := &connection.Record{
		ConnectionID: randomString(), ThreadID: id,
		Namespace: findNamespace(RequestMsgType), State: (&null{}).Name(),
	}

	err = svc.connectionRecorder.SaveConnectionRecordWithMappings(connRec)
	require.NoError(t, err)

	_, err = svc.HandleInbound(
		generateRequestMsgPayload(t, &protocol.MockProvider{}, id, randomString()),
		service.EmptyDIDCommContext())
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestEventStoreError(t *testing.T) {
	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			e.Continue = func(args interface{}) {
				svc.processCallback(&message{Msg: service.NewDIDCommMsgMap(struct{}{})})
			}
			e.Continue(&service.Empty{})
		}
	}()

	_, err = svc.HandleInbound(
		generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString(), randomString()),
		service.EmptyDIDCommContext())
	require.NoError(t, err)
}

func TestEventProcessCallback(t *testing.T) {
	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)

	msg := &message{
		ThreadID: threadIDValue,
		Msg:      service.NewDIDCommMsgMap(model.Ack{Type: AckMsgType}),
	}

	err = svc.handleWithoutAction(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid state name: invalid state name ")
}

func validateState(t *testing.T, svc *Service, id, namespace, expected string) {
	nsThid, err := connection.CreateNamespaceKey(namespace, id)
	require.NoError(t, err)
	s, err := svc.currentState(nsThid)
	require.NoError(t, err)
	require.Equal(t, expected, s.Name())
}

func TestServiceErrors(t *testing.T) {
	requestBytes, err := json.Marshal(
		&Request{
			Type:  ResponseMsgType,
			ID:    randomString(),
			Label: "test",
		},
	)
	require.NoError(t, err)

	msg, err := service.ParseDIDCommMsgMap(requestBytes)
	require.NoError(t, err)

	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	// fetch current state error
	mockStore := &mockStore{get: func(s string) (bytes []byte, e error) {
		return nil, errors.New("error")
	}}

	prov := &protocol.MockProvider{
		ProtocolStateStoreProvider: mockstorage.NewCustomMockStoreProvider(
			mockStore,
		),
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	}
	svc, err = New(prov)
	require.NoError(t, err)

	payload := generateRequestMsgPayload(t, prov, randomString(), "")
	_, err = svc.HandleInbound(payload, service.EmptyDIDCommContext())
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot fetch state from store")

	svc, err = New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)

	// invalid message type
	msg["@type"] = "invalid"
	svc.connectionRecorder, err = connection.NewRecorder(&protocol.MockProvider{})
	require.NoError(t, err)

	_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unrecognized msgType: invalid")

	// test handle - invalid state name
	msg["@type"] = ResponseMsgType
	m := &message{Msg: msg, ThreadID: randomString()}
	err = svc.handleWithoutAction(m)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid state name:")

	// invalid state name
	m.NextStateName = StateIDInvited
	m.ConnRecord = &connection.Record{ConnectionID: "abc"}
	err = svc.handleWithoutAction(m)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to execute state 'invited':")
}

func TestHandleOutbound(t *testing.T) {
	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)

	_, err = svc.HandleOutbound(service.DIDCommMsgMap{}, "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestConnectionRecord(t *testing.T) {
	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NoError(t, err)

	conn, err := svc.connectionRecord(generateRequestMsgPayload(t, &protocol.MockProvider{},
		randomString(), randomString()), service.EmptyDIDCommContext())
	require.NoError(t, err)
	require.NotNil(t, conn)

	// invalid type
	requestBytes, err := json.Marshal(&Request{
		Type: "invalid-type",
	})
	require.NoError(t, err)
	msg, err := service.ParseDIDCommMsgMap(requestBytes)
	require.NoError(t, err)

	_, err = svc.connectionRecord(msg, service.EmptyDIDCommContext())
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid message type")
}

func TestInvitationRecord(t *testing.T) {
	sp := mockstorage.NewMockStoreProvider()
	k := newKMS(t, sp)
	ctx := &context{
		kms:              k,
		keyType:          kms.ED25519Type,
		keyAgreementType: kms.X25519ECDHKWType,
	}
	svc, err := New(&protocol.MockProvider{
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		KeyTypeValue:          ctx.keyType,
		KeyAgreementTypeValue: ctx.keyAgreementType,
	})
	require.NoError(t, err)

	_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)
	invitationBytes, err := json.Marshal(&Invitation{
		Type:          InvitationMsgType,
		ID:            "id",
		RecipientKeys: []string{base58.Encode(verPubKey)},
	})
	require.NoError(t, err)

	msg, err := service.ParseDIDCommMsgMap(invitationBytes)
	require.NoError(t, err)

	conn, err := svc.invitationMsgRecord(msg)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// invalid thread id
	invitationBytes, err = json.Marshal(&Invitation{
		Type: "invalid-type",
	})
	require.NoError(t, err)
	msg, err = service.ParseDIDCommMsgMap(invitationBytes)
	require.NoError(t, err)

	_, err = svc.invitationMsgRecord(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threadID not found")

	// db error
	svc, err = New(&protocol.MockProvider{
		ProtocolStateStoreProvider: mockstorage.NewCustomMockStoreProvider(&mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry), ErrPut: errors.New("db error"),
		}),
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
	})
	require.NotNil(t, svc.connectionRecorder)
	require.NoError(t, err)

	invitationBytes, err = json.Marshal(&Invitation{
		Type:          InvitationMsgType,
		ID:            "id",
		RecipientKeys: []string{base58.Encode(verPubKey)},
	})
	require.NoError(t, err)

	msg, err = service.ParseDIDCommMsgMap(invitationBytes)
	require.NoError(t, err)

	_, err = svc.invitationMsgRecord(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "save connection record")
}

func TestRequestRecord(t *testing.T) {
	t.Run("returns connection record", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		didcommMsg := generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString(), uuid.New().String())
		require.NotEmpty(t, didcommMsg.ParentThreadID())
		conn, err := svc.requestMsgRecord(didcommMsg, service.EmptyDIDCommContext())
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.Equal(t, didcommMsg.ParentThreadID(), conn.InvitationID)
	})

	t.Run("returns connection record from request without connection DIDDoc field", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		didcommMsg := generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString(), uuid.New().String())
		require.NotEmpty(t, didcommMsg.ParentThreadID())
		delete(didcommMsg, "connection")

		_, err = svc.requestMsgRecord(didcommMsg, service.EmptyDIDCommContext())
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing connection field")
	})

	t.Run("fails on db error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ProtocolStateStoreProvider: mockstorage.NewCustomMockStoreProvider(
				&mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry), ErrPut: errors.New("db error")},
			),
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NotNil(t, svc.connectionRecorder)
		require.NoError(t, err)

		_, err = svc.requestMsgRecord(generateRequestMsgPayload(t, &protocol.MockProvider{},
			randomString(), uuid.New().String()), service.EmptyDIDCommContext())
		require.Error(t, err)
		require.Contains(t, err.Error(), "save connection record")
	})

	t.Run("fails if parent thread ID is missing", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		parentThreadID := ""
		didcommMsg := generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString(), parentThreadID)
		require.Empty(t, didcommMsg.ParentThreadID())
		_, err = svc.requestMsgRecord(didcommMsg, service.EmptyDIDCommContext())
		require.Error(t, err)
	})
}

func TestAcceptConnectionRequest(t *testing.T) {
	sp := mockstorage.NewMockStoreProvider()
	k := newKMS(t, sp)
	ctx := &context{
		kms:              k,
		keyType:          kms.ED25519Type,
		keyAgreementType: kms.X25519ECDHKWType,
	}

	svc, err := New(&protocol.MockProvider{
		StoreProvider: sp,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		CustomKMS:             k,
		KeyTypeValue:          ctx.keyType,
		KeyAgreementTypeValue: ctx.keyAgreementType,
	})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	invitation := &Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{base58.Encode(verPubKey)},
		ServiceEndpoint: "http://alice.agent.example.com:8081",
	}

	err = svc.connectionRecorder.SaveInvitation(invitation.ID, invitation)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			prop, ok := e.Properties.(event)
			require.True(t, ok, "Failed to cast the event properties to service.Event")
			require.NoError(t, svc.AcceptConnectionRequest(prop.ConnectionID(), "", "", nil))
		}
	}()

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for e := range statusCh {
			if e.Type == service.PostState && e.StateID == StateIDResponded {
				done <- struct{}{}
			}
		}
	}()

	_, err = svc.HandleInbound(generateRequestMsgPayload(t, &protocol.MockProvider{
		StoreProvider: mockstorage.NewMockStoreProvider(),
	}, randomString(), invitation.ID), service.EmptyDIDCommContext())
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestAcceptConnectionRequestWithoutParentThreadID(t *testing.T) {
	sp := mockstorage.NewMockStoreProvider()
	k := newKMS(t, sp)
	ctx := &context{
		kms:              k,
		keyType:          kms.ED25519Type,
		keyAgreementType: kms.X25519ECDHKWType,
	}

	svc, err := New(&protocol.MockProvider{
		StoreProvider: sp,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		CustomKMS:             k,
		KeyTypeValue:          ctx.keyType,
		KeyAgreementTypeValue: ctx.keyAgreementType,
	})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	invitation := &Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{base58.Encode(verPubKey)},
		ServiceEndpoint: "http://alice.agent.example.com:8081",
	}

	err = svc.connectionRecorder.SaveInvitation(invitation.ID, invitation)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			prop, ok := e.Properties.(event)
			require.True(t, ok, "Failed to cast the event properties to service.Event")
			require.NoError(t, svc.AcceptConnectionRequest(prop.ConnectionID(), "", "", nil))
		}
	}()

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for e := range statusCh {
			if e.Type == service.PostState && e.StateID == StateIDResponded {
				done <- struct{}{}
			}
		}
	}()

	props := map[string]interface{}{}
	props[InvitationRecipientKey] = invitation.RecipientKeys[0]
	c := service.NewDIDCommContext("", "", props)

	_, err = svc.HandleInbound(generateRequestMsgPayload(t, &protocol.MockProvider{
		StoreProvider: mockstorage.NewMockStoreProvider(),
	}, randomString(), ""), c)
	require.NoError(t, err, "missing parent thread ID and invitation recipient key on connection request")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestAcceptConnectionRequestWithPublicDID(t *testing.T) {
	sp := mockstorage.NewMockStoreProvider()
	k := newKMS(t, sp)
	ctx := &context{
		kms:              k,
		keyType:          kms.ED25519Type,
		keyAgreementType: kms.X25519ECDHKWType,
	}
	svc, err := New(&protocol.MockProvider{
		StoreProvider: sp,
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		KeyTypeValue:          ctx.keyType,
		KeyAgreementTypeValue: ctx.keyAgreementType,
	})
	require.NoError(t, err)

	const publicDIDMethod = "sidetree"
	publicDID := fmt.Sprintf("did:%s:123456", publicDIDMethod)
	doc, err := svc.ctx.vdRegistry.Create(publicDIDMethod, nil)
	require.NoError(t, err)

	svc.ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: doc.DIDDocument}

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	invitation := &Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{base58.Encode(verPubKey)},
		ServiceEndpoint: "http://alice.agent.example.com:8081",
	}

	err = svc.connectionRecorder.SaveInvitation(invitation.ID, invitation)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			prop, ok := e.Properties.(event)
			require.True(t, ok, "Failed to cast the event properties to service.Event")
			require.NoError(t, svc.AcceptConnectionRequest(prop.ConnectionID(), publicDID, "sample-label", nil))
		}
	}()

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for e := range statusCh {
			if e.Type == service.PostState && e.StateID == StateIDResponded {
				done <- struct{}{}
			}
		}
	}()

	_, err = svc.HandleInbound(generateRequestMsgPayload(t, &protocol.MockProvider{
		StoreProvider: mockstorage.NewMockStoreProvider(),
	}, randomString(), invitation.ID), service.EmptyDIDCommContext())
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestAcceptInvitation(t *testing.T) {
	t.Run("accept invitation - success", func(t *testing.T) {
		sp := mockstorage.NewMockStoreProvider()
		k := newKMS(t, sp)
		ctx := &context{
			kms:              k,
			keyType:          kms.ED25519Type,
			keyAgreementType: kms.X25519ECDHKWType,
		}
		svc, err := New(&protocol.MockProvider{
			StoreProvider: sp,
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			CustomKMS:             k,
			KeyTypeValue:          ctx.keyType,
			KeyAgreementTypeValue: ctx.keyAgreementType,
		})
		require.NoError(t, err)

		actionCh := make(chan service.DIDCommAction, 10)
		err = svc.RegisterActionEvent(actionCh)
		require.NoError(t, err)

		go func() {
			for e := range actionCh {
				_, ok := e.Properties.(event)
				require.True(t, ok, "Failed to cast the event properties to service.Event")

				// ignore action event
			}
		}()

		statusCh := make(chan service.StateMsg, 10)
		err = svc.RegisterMsgEvent(statusCh)
		require.NoError(t, err)

		done := make(chan struct{})

		go func() {
			for e := range statusCh {
				prop, ok := e.Properties.(event)
				if !ok {
					require.Fail(t, "Failed to cast the event properties to service.Event")
				}

				if e.Type == service.PostState && e.StateID == StateIDInvited {
					require.NoError(t, svc.AcceptInvitation(prop.ConnectionID(), "", "", nil))
				}

				if e.Type == service.PostState && e.StateID == StateIDRequested {
					done <- struct{}{}
				}
			}
		}()
		_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		invitationBytes, err := json.Marshal(&Invitation{
			Type:          InvitationMsgType,
			ID:            generateRandomID(),
			RecipientKeys: []string{base58.Encode(verPubKey)},
		})
		require.NoError(t, err)

		didMsg, err := service.ParseDIDCommMsgMap(invitationBytes)
		require.NoError(t, err)

		_, err = svc.HandleInbound(didMsg, service.EmptyDIDCommContext())
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated")
		}
	})

	t.Run("accept invitation - error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		err = svc.AcceptInvitation(generateRandomID(), "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "accept connection invitation : get protocol state data : data not found")
	})

	t.Run("accept invitation - state error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		id := generateRandomID()
		connRecord := &connection.Record{
			ConnectionID: id,
			State:        StateIDRequested,
		}
		err = svc.connectionRecorder.SaveConnectionRecord(connRecord)
		require.NoError(t, err)

		err = svc.storeEventProtocolStateData(&message{ConnRecord: connRecord})
		require.NoError(t, err)

		err = svc.AcceptInvitation(id, "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "current state (requested) is different from expected state (invited)")
	})

	t.Run("accept invitation - no connection record error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		id := generateRandomID()
		connRecord := &connection.Record{
			ConnectionID: id,
			State:        StateIDRequested,
		}

		err = svc.storeEventProtocolStateData(&message{ConnRecord: connRecord})
		require.NoError(t, err)

		err = svc.AcceptInvitation(id, "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "accept connection invitation : data not found")
	})
}

func TestAcceptInvitationWithPublicDID(t *testing.T) {
	t.Run("accept invitation with public DID - success", func(t *testing.T) {
		sp := mockstorage.NewMockStoreProvider()
		k := newKMS(t, sp)
		ctx := &context{
			kms:              k,
			keyType:          kms.ED25519Type,
			keyAgreementType: kms.X25519ECDHKWType,
		}
		svc, err := New(&protocol.MockProvider{
			StoreProvider: sp,
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
			KeyTypeValue:          ctx.keyType,
			KeyAgreementTypeValue: ctx.keyAgreementType,
		})
		require.NoError(t, err)

		const publicDIDMethod = "sidetree"
		publicDID := fmt.Sprintf("did:%s:123456", publicDIDMethod)
		doc, err := svc.ctx.vdRegistry.Create(publicDIDMethod, nil)
		require.NoError(t, err)
		svc.ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: doc.DIDDocument}

		actionCh := make(chan service.DIDCommAction, 10)
		err = svc.RegisterActionEvent(actionCh)
		require.NoError(t, err)

		go func() {
			for e := range actionCh {
				_, ok := e.Properties.(event)
				require.True(t, ok, "Failed to cast the event properties to service.Event")

				// ignore action event
			}
		}()

		statusCh := make(chan service.StateMsg, 10)
		err = svc.RegisterMsgEvent(statusCh)
		require.NoError(t, err)

		done := make(chan struct{})

		go func() {
			for e := range statusCh {
				prop, ok := e.Properties.(event)
				if !ok {
					require.Fail(t, "Failed to cast the event properties to service.Event")
				}

				if e.Type == service.PostState && e.StateID == StateIDInvited {
					require.NoError(t, svc.AcceptInvitation(prop.ConnectionID(), publicDID, "sample-label", nil))
				}

				if e.Type == service.PostState && e.StateID == StateIDRequested {
					done <- struct{}{}
				}
			}
		}()

		_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		invitationBytes, err := json.Marshal(&Invitation{
			Type:          InvitationMsgType,
			ID:            generateRandomID(),
			RecipientKeys: []string{base58.Encode(verPubKey)},
		})
		require.NoError(t, err)

		didMsg, err := service.ParseDIDCommMsgMap(invitationBytes)
		require.NoError(t, err)

		_, err = svc.HandleInbound(didMsg, service.EmptyDIDCommContext())
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated")
		}
	})

	t.Run("accept invitation - error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		err = svc.AcceptInvitation(generateRandomID(), "sample-public-did", "sample-label", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "accept connection invitation : get protocol state data : data not found")
	})

	t.Run("accept invitation - state error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		id := generateRandomID()
		connRecord := &connection.Record{
			ConnectionID: id,
			State:        StateIDRequested,
		}
		err = svc.connectionRecorder.SaveConnectionRecord(connRecord)
		require.NoError(t, err)

		err = svc.storeEventProtocolStateData(&message{ConnRecord: connRecord})
		require.NoError(t, err)

		err = svc.AcceptInvitation(id, "sample-public-did", "sample-label", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "current state (requested) is different from expected state (invited)")
	})

	t.Run("accept invitation - no connection record error", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		id := generateRandomID()
		connRecord := &connection.Record{
			ConnectionID: id,
			State:        StateIDRequested,
		}

		err = svc.storeEventProtocolStateData(&message{ConnRecord: connRecord})
		require.NoError(t, err)

		err = svc.AcceptInvitation(id, "sample-public-did", "sample-label", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "accept connection invitation : data not found")
	})
}

func TestEventProtocolStateData(t *testing.T) {
	t.Run("event protocol state data - success", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		connID := generateRandomID()

		msg := &message{
			ConnRecord: &connection.Record{ConnectionID: connID},
		}
		err = svc.storeEventProtocolStateData(msg)
		require.NoError(t, err)

		retrievedMsg, err := svc.getEventProtocolStateData(connID)
		require.NoError(t, err)
		require.Equal(t, msg, retrievedMsg)
	})

	t.Run("event protocol state data - data not found", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		err = svc.AcceptConnectionRequest(generateRandomID(), "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "accept exchange request : get protocol state data : data not found")

		err = svc.AcceptConnectionRequest(generateRandomID(), "sample-public-did", "sample-label", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "accept exchange request : get protocol state data : data not found")
	})

	t.Run("event protocol state data - invalid data", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		connID := generateRandomID()

		err = svc.connectionRecorder.SaveEvent(connID, []byte("invalid data"))
		require.NoError(t, err)

		_, err = svc.getEventProtocolStateData(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get protocol state data : invalid character")
	})
}

func TestNextState(t *testing.T) {
	t.Run("empty thread ID", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		_, err = svc.nextState(RequestMsgType, "")
		require.EqualError(t, err, "unable to compute hash, empty bytes")
	})

	t.Run("valid inputs", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		s, errState := svc.nextState(RequestMsgType, generateRandomID())
		require.NoError(t, errState)
		require.Equal(t, StateIDRequested, s.Name())
	})
}

func TestFetchConnectionRecord(t *testing.T) {
	t.Run("fetch connection record - invalid payload", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		_, err = svc.fetchConnectionRecord("", service.DIDCommMsgMap{"~thread": map[int]int{1: 1}})
		require.Contains(t, fmt.Sprintf("%v", err), `'~thread' needs a map with string keys`)
	})

	t.Run("fetch connection record - no thread id", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		_, err = svc.fetchConnectionRecord(theirNSPrefix, toDIDCommMsg(t, &Request{
			Type: ResponseMsgType,
			ID:   generateRandomID(),
		}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to compute hash, empty bytes")
	})

	t.Run("fetch connection record - valid input", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)

		_, err = svc.fetchConnectionRecord(theirNSPrefix, toDIDCommMsg(t, &Response{
			Type:   ResponseMsgType,
			ID:     generateRandomID(),
			Thread: &decorator.Thread{ID: generateRandomID()},
		}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get connectionID by namespaced threadID: data not found")
	})
}

func generateRequestMsgPayload(t *testing.T, prov provider, id, invitationID string) service.DIDCommMsgMap {
	connRec, err := connection.NewRecorder(prov)
	require.NoError(t, err)
	require.NotNil(t, connRec)

	ctx := context{
		outboundDispatcher: prov.OutboundDispatcher(),
		vdRegistry:         &mockvdr.MockVDRegistry{CreateValue: mockdiddoc.GetMockDIDDoc(t, false)},
		connectionRecorder: connRec,
	}
	doc, err := ctx.vdRegistry.Create(testMethod, nil)
	require.NoError(t, err)

	requestBytes, err := json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   id,
		Thread: &decorator.Thread{
			PID: invitationID,
		},
		Connection: &Connection{
			DID:    doc.DIDDocument.ID,
			DIDDoc: doc.DIDDocument,
		},
	})
	require.NoError(t, err)

	didMsg, err := service.ParseDIDCommMsgMap(requestBytes)
	require.NoError(t, err)

	return didMsg
}

func TestService_CreateImplicitInvitation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		routeSvc := &mockroute.MockMediatorSvc{}
		prov := &protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: routeSvc,
			},
		}
		sp := mockstorage.NewMockStoreProvider()
		k := newKMS(t, sp)
		ctx := &context{
			kms:                k,
			outboundDispatcher: prov.OutboundDispatcher(),
			routeSvc:           routeSvc,
			keyType:            kms.ED25519Type,
			keyAgreementType:   kms.X25519ECDHKWType,
			mediaTypeProfiles:  []string{transport.MediaTypeRFC0019EncryptedEnvelope},
		}

		_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		newDIDDoc := createDIDDocWithKey(verPubKey)

		connRec, err := connection.NewRecorder(prov)
		require.NoError(t, err)
		require.NotNil(t, connRec)

		didConnStore, err := didstore.NewConnectionStore(prov)
		require.NoError(t, err)
		require.NotNil(t, didConnStore)

		ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: newDIDDoc}
		ctx.connectionRecorder = connRec
		ctx.connectionStore = didConnStore

		s, err := New(prov)
		require.NoError(t, err)

		s.ctx = ctx
		connID, err := s.CreateImplicitInvitation("label", newDIDDoc.ID, "", "", nil)
		require.NoError(t, err)
		require.NotEmpty(t, connID)
	})

	t.Run("error during did resolution", func(t *testing.T) {
		routeSvc := &mockroute.MockMediatorSvc{}
		prov := &protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: routeSvc,
			},
		}
		sp := mockstorage.NewMockStoreProvider()
		k := newKMS(t, sp)
		ctx := &context{
			kms:                k,
			outboundDispatcher: prov.OutboundDispatcher(),
			routeSvc:           routeSvc,
			keyType:            kms.ED25519Type,
			keyAgreementType:   kms.X25519ECDHKWType,
			mediaTypeProfiles:  []string{transport.MediaTypeRFC0019EncryptedEnvelope},
		}

		_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		newDIDDoc := createDIDDocWithKey(verPubKey)

		connRec, err := connection.NewRecorder(prov)
		require.NoError(t, err)
		require.NotNil(t, connRec)

		didConnStore, err := didstore.NewConnectionStore(prov)
		require.NoError(t, err)
		require.NotNil(t, didConnStore)

		ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveErr: errors.New("resolve error")}
		ctx.connectionRecorder = connRec
		ctx.connectionStore = didConnStore

		s, err := New(prov)
		require.NoError(t, err)
		s.ctx = ctx

		connID, err := s.CreateImplicitInvitation("label", newDIDDoc.ID, "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")
		require.Empty(t, connID)
	})

	t.Run("error during saving connection", func(t *testing.T) {
		sp := mockstorage.NewMockStoreProvider()
		k := newKMS(t, sp)
		ctx := &context{
			kms:               k,
			keyType:           kms.ED25519Type,
			keyAgreementType:  kms.X25519ECDHKWType,
			mediaTypeProfiles: []string{transport.MediaTypeRFC0019EncryptedEnvelope},
		}
		routeSvc := &mockroute.MockMediatorSvc{}
		protocolStateStore := mockstorage.NewMockStoreProvider()
		protocolStateStore.Store.ErrPut = errors.New("store put error")
		prov := &protocol.MockProvider{
			ProtocolStateStoreProvider: protocolStateStore,
			ServiceMap: map[string]interface{}{
				mediator.Coordination: routeSvc,
			},
			KeyTypeValue:          ctx.keyType,
			KeyAgreementTypeValue: ctx.keyAgreementType,
		}

		ctx.outboundDispatcher = prov.OutboundDispatcher()
		ctx.routeSvc = routeSvc

		_, verPubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		newDIDDoc := createDIDDocWithKey(verPubKey)

		connRec, err := connection.NewRecorder(prov)
		require.NoError(t, err)
		require.NotNil(t, connRec)

		didConnStore, err := didstore.NewConnectionStore(prov)
		require.NoError(t, err)
		require.NotNil(t, didConnStore)

		ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: newDIDDoc}
		ctx.connectionRecorder = connRec
		ctx.connectionStore = didConnStore

		s, err := New(prov)
		require.NoError(t, err)
		s.ctx = ctx

		connID, err := s.CreateImplicitInvitation("label", newDIDDoc.ID, "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store put error")
		require.Empty(t, connID)
	})
}

func testProvider() *protocol.MockProvider {
	return &protocol.MockProvider{
		StoreProvider: mockstorage.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		KeyTypeValue:          kms.ED25519Type,
		KeyAgreementTypeValue: kms.X25519ECDHKWType,
	}
}

func newPeerDID(t *testing.T, k kms.KeyManager) *did.Doc {
	kid, pubKey, err := k.CreateAndExportPubKeyBytes(kms.ED25519)
	require.NoError(t, err)

	key := did.VerificationMethod{
		ID:         kid,
		Type:       "Ed25519VerificationKey2018",
		Controller: "",
		Value:      pubKey,
	}
	doc, err := peer.NewDoc(
		[]did.VerificationMethod{key},
		did.WithAuthentication([]did.Verification{{
			VerificationMethod: key,
			Relationship:       0,
			Embedded:           true,
		}}),
		did.WithService([]did.Service{{
			ID:              "didcomm",
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{base58.Encode(pubKey)},
			ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("http://example.com"),
		}}),
	)
	require.NoError(t, err)

	return doc
}

type mockConnectionStore struct {
	saveDIDByResolvingErr error
	saveDIDFromDocErr     error
}

// GetDID returns DID associated with key.
func (m *mockConnectionStore) GetDID(string) (string, error) {
	return "", nil
}

// SaveDID saves DID to the underlying storage.
func (m *mockConnectionStore) SaveDID(string, ...string) error {
	return nil
}

// SaveDIDFromDoc saves DID from did.Doc to the underlying storage.
func (m *mockConnectionStore) SaveDIDFromDoc(*did.Doc) error {
	return m.saveDIDFromDocErr
}

// SaveDIDByResolving saves DID resolved by VDR to the underlying storage.
func (m *mockConnectionStore) SaveDIDByResolving(string, ...string) error {
	return m.saveDIDByResolvingErr
}

func randomString() string {
	u := uuid.New()
	return u.String()
}
