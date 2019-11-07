/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockdidresolver "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didresolver"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockdid "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdr/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const testMethod = "peer"

type event interface {
	// connection ID
	ConnectionID() string

	// invitation ID
	InvitationID() string
}

func TestService_Name(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		prov, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
		require.NoError(t, err)
		require.Equal(t, DIDExchange, prov.Name())
	})
}

func TestServiceNew(t *testing.T) {
	t.Run("test error from open store", func(t *testing.T) {
		_, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()},
			&protocol.MockProvider{StoreProvider: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})

	t.Run("test error from open transient store", func(t *testing.T) {
		_, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()},
			&protocol.MockProvider{TransientStoreProvider: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open transient store")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open transient store")
	})
}

// did-exchange flow with role Inviter
func TestService_Handle_Inviter(t *testing.T) {
	prov := protocol.MockProvider{}
	pubKey, privKey := generateKeyPair()
	ctx := &context{
		outboundDispatcher: prov.OutboundDispatcher(),
		didCreator:         &mockdid.MockDIDCreator{Doc: createDIDDocWithKey(pubKey)},
		signer:             &mockSigner{privateKey: privKey},
	}

	newDidDoc, err := ctx.didCreator.Create(testMethod)
	require.NoError(t, err)

	s, err := New(&mockdid.MockDIDCreator{Doc: createDIDDocWithKey(pubKey)}, &protocol.MockProvider{})
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

	go func() { require.NoError(t, service.AutoExecuteActionEvent(actionCh)) }()

	thid := randomString()

	// Invitation was previously sent by Alice to Bob.
	// Bob now sends a did-exchange Request
	payloadBytes, err := json.Marshal(
		&Request{
			Type:  RequestMsgType,
			ID:    thid,
			Label: "Bob",
			Connection: &Connection{
				DID:    "did:peer:did@B:A",
				DIDDoc: newDidDoc,
			},
		})
	require.NoError(t, err)
	msg, err := service.NewDIDCommMsg(payloadBytes)
	require.NoError(t, err)
	_, err = s.HandleInbound(msg)
	require.NoError(t, err)

	select {
	case <-respondedFlag:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event responded")
	}
	// Alice automatically sends exchange Response to Bob
	// Bob replies with an ACK
	payloadBytes, err = json.Marshal(
		&model.Ack{
			Type:   AckMsgType,
			ID:     randomString(),
			Status: "OK",
			Thread: &decorator.Thread{ID: thid},
		})
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(payloadBytes)
	require.NoError(t, err)

	_, err = s.HandleInbound(didMsg)
	require.NoError(t, err)

	select {
	case <-completedFlag:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event complete")
	}

	validateState(t, s, thid, findNameSpace(AckMsgType), (&completed{}).Name())
}

func msgEventListener(t *testing.T, statusCh chan service.StateMsg, respondedFlag, completedFlag chan struct{}) {
	for e := range statusCh {
		require.Equal(t, DIDExchange, e.ProtocolName)

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

// did-exchange flow with role Invitee
func TestService_Handle_Invitee(t *testing.T) {
	store := mockstorage.NewMockStoreProvider()
	prov := protocol.MockProvider{}
	pubKey, privKey := generateKeyPair()
	ctx := context{
		outboundDispatcher: prov.OutboundDispatcher(),
		didCreator:         &mockdid.MockDIDCreator{Doc: createDIDDocWithKey(pubKey)},
		signer:             &mockSigner{privateKey: privKey},
	}

	newDidDoc, err := ctx.didCreator.Create(testMethod)
	require.NoError(t, err)

	s, err := New(&mockdid.MockDIDCreator{
		Doc: createDIDDocWithKey(pubKey)},
		&protocol.MockProvider{TransientStoreProvider: store})
	require.NoError(t, err)

	s.ctx.didResolver = &mockdidresolver.MockResolver{Doc: newDidDoc}
	actionCh := make(chan service.DIDCommAction, 10)
	err = s.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	statusCh := make(chan service.StateMsg, 10)
	err = s.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	requestedCh := make(chan struct{})
	completedCh := make(chan struct{})

	go handleMessagesInvitee(statusCh, requestedCh, completedCh)

	go func() { require.NoError(t, service.AutoExecuteActionEvent(actionCh)) }()

	// Alice receives an invitation from Bob
	payloadBytes, err := json.Marshal(
		&Invitation{
			Type:  InvitationMsgType,
			ID:    randomString(),
			Label: "Bob",
		},
	)
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(payloadBytes)
	require.NoError(t, err)

	_, err = s.HandleInbound(didMsg)
	require.NoError(t, err)

	select {
	case <-requestedCh:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event requested")
	}

	// Alice automatically sends a Request to Bob and is now in REQUESTED state.
	connRecord := &ConnectionRecord{}

	for _, v := range store.Store.Store {
		err = json.Unmarshal(v, connRecord)
		if err == nil && (&requested{}).Name() == connRecord.State {
			break
		}
	}

	require.Equal(t, (&requested{}).Name(), connRecord.State)

	connection := &Connection{
		DID:    newDidDoc.ID,
		DIDDoc: newDidDoc,
	}

	connectionSignature, err := ctx.prepareConnectionSignature(connection)
	require.NoError(t, err)

	// Bob replies with a Response
	payloadBytes, err = json.Marshal(
		&Response{
			Type:                ResponseMsgType,
			ID:                  randomString(),
			ConnectionSignature: connectionSignature,
			Thread:              &decorator.Thread{ID: connRecord.ThreadID},
		},
	)
	require.NoError(t, err)

	didMsg, err = service.NewDIDCommMsg(payloadBytes)
	require.NoError(t, err)

	_, err = s.HandleInbound(didMsg)
	require.NoError(t, err)

	// Alice automatically sends an ACK to Bob
	// Alice must now be in COMPLETED state
	select {
	case <-completedCh:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event complete")
	}

	validateState(t, s, connRecord.ThreadID, findNameSpace(ResponseMsgType), (&completed{}).Name())
}

func handleMessagesInvitee(statusCh chan service.StateMsg, requestedCh, completedCh chan struct{}) {
	for e := range statusCh {
		if e.Type == service.PostState {
			// receive the events
			if e.StateID == stateNameCompleted {
				close(completedCh)
			} else if e.StateID == stateNameRequested {
				close(requestedCh)
			}
		}
	}
}

func TestService_Handle_EdgeCases(t *testing.T) {
	t.Run("handleInbound - no action events registered", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
		require.NoError(t, err)

		_, err = svc.HandleInbound(&service.DIDCommMsg{
			Header: &service.Header{Type: ResponseMsgType},
		})
		require.EqualError(t, err, "no clients are registered to handle the message")
	})

	t.Run("handleInbound - must not transition to same state", func(t *testing.T) {
		s, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
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

		didMsg, err := service.NewDIDCommMsg(response)
		require.NoError(t, err)

		_, err = s.HandleInbound(didMsg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "handle inbound - next state : invalid state transition: "+
			"null -> responded")
	})

	t.Run("handleInbound - threadID error", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
		require.NoError(t, err)

		err = svc.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)

		requestBytes, err := json.Marshal(&Request{
			Type: RequestMsgType,
		})
		require.NoError(t, err)

		didMsg, err := service.NewDIDCommMsg(requestBytes)
		require.NoError(t, err)

		_, err = svc.HandleInbound(didMsg)
		require.Error(t, err)
		require.Equal(t, err.Error(), "threadID not found")
	})

	t.Run("handleInbound - connection record error", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
		require.NoError(t, err)

		err = svc.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)

		transientStore := &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("db error")}
		svc.connectionStore = NewConnectionRecorder(transientStore, nil)

		_, err = svc.HandleInbound(generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString()))
		require.Error(t, err)
		require.Contains(t, err.Error(), "save connection record")
	})

	t.Run("handleInbound - send action event error", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
		require.NoError(t, err)

		err = svc.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)

		svc.connectionStore.transientStore = &mockStore{
			get: func(s string) (bytes []byte, e error) {
				return nil, storage.ErrDataNotFound
			},
			put: func(s string, bytes []byte) error {
				if strings.Contains(s, "didex-event-") {
					return errors.New("db error")
				}

				return nil
			},
		}

		requestBytes, err := json.Marshal(&Request{
			Type: RequestMsgType,
			ID:   generateRandomID(),
			Connection: &Connection{
				DID: "xyz",
			},
		})
		require.NoError(t, err)

		// send invite
		didMsg, err := service.NewDIDCommMsg(requestBytes)
		require.NoError(t, err)

		_, err = svc.HandleInbound(didMsg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "handle inbound : send action event")
	})
}

func TestService_Accept(t *testing.T) {
	s := &Service{}

	require.Equal(t, true, s.Accept("https://didcomm.org/didexchange/1.0/invitation"))
	require.Equal(t, true, s.Accept("https://didcomm.org/didexchange/1.0/request"))
	require.Equal(t, true, s.Accept("https://didcomm.org/didexchange/1.0/response"))
	require.Equal(t, true, s.Accept("https://didcomm.org/didexchange/1.0/ack"))
	require.Equal(t, false, s.Accept("unsupported msg type"))
}

func TestService_threadID(t *testing.T) {
	t.Run("returns new thid for ", func(t *testing.T) {
		thid, err := threadID(&service.DIDCommMsg{Header: &service.Header{Type: InvitationMsgType}})
		require.NoError(t, err)
		require.NotNil(t, thid)
	})

	t.Run("returns unmarshall error", func(t *testing.T) {
		_, err := threadID(&service.DIDCommMsg{Header: &service.Header{Type: RequestMsgType}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "threadID not found")
	})
}

func TestService_CurrentState(t *testing.T) {
	t.Run("null state if not found in store", func(t *testing.T) {
		svc := &Service{
			connectionStore: NewConnectionRecorder(&mockStore{
				get: func(string) ([]byte, error) { return nil, storage.ErrDataNotFound },
			}, nil),
		}
		thid, err := createNSKey(theirNSPrefix, "ignored")
		require.NoError(t, err)
		s, err := svc.currentState(thid)
		require.NoError(t, err)
		require.Equal(t, (&null{}).Name(), s.Name())
	})

	t.Run("returns state from store", func(t *testing.T) {
		expected := &requested{}
		connRec, err := json.Marshal(&ConnectionRecord{State: expected.Name()})
		require.NoError(t, err)
		svc := &Service{
			connectionStore: NewConnectionRecorder(&mockStore{
				get: func(string) ([]byte, error) { return connRec, nil },
			}, nil),
		}
		thid, err := createNSKey(theirNSPrefix, "ignored")
		require.NoError(t, err)
		actual, err := svc.currentState(thid)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})

	t.Run("forwards generic error from store", func(t *testing.T) {
		svc := &Service{
			connectionStore: NewConnectionRecorder(&mockStore{
				get: func(string) ([]byte, error) {
					return nil, errors.New("test")
				},
			}, nil),
		}
		thid, err := createNSKey(theirNSPrefix, "ignored")
		require.NoError(t, err)
		_, err = svc.currentState(thid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot fetch state from store")
	})
}

func TestService_Update(t *testing.T) {
	s := &requested{}
	data := make(map[string][]byte)
	connRec := &ConnectionRecord{ThreadID: "123", ConnectionID: "123456", State: s.Name(),
		Namespace: findNameSpace(RequestMsgType)}
	bytes, err := json.Marshal(connRec)
	require.NoError(t, err)

	svc := &Service{
		connectionStore: NewConnectionRecorder(&mockStore{
			put: func(k string, v []byte) error {
				data[k] = bytes
				return nil
			},
			get: func(k string) ([]byte, error) {
				return bytes, nil
			},
		}, nil),
	}

	require.NoError(t, svc.update(RequestMsgType, connRec))

	cr := &ConnectionRecord{}
	err = json.Unmarshal(bytes, cr)
	require.NoError(t, err)
	require.Equal(t, cr, connRec)
}

type mockStore struct {
	put func(string, []byte) error
	get func(string) ([]byte, error)
}

// Put stores the key and the record
func (m *mockStore) Put(k string, v []byte) error {
	return m.put(k, v)
}

// Get fetches the record based on key
func (m *mockStore) Get(k string) ([]byte, error) {
	return m.get(k)
}

// Search returns storage iterator
func (m *mockStore) Iterator(start, limit string) storage.StoreIterator {
	return nil
}

func getMockDID() *did.Doc {
	return &did.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      "did:peer:123456789abcdefghi#inbox",
		Service: []did.Service{
			{
				ServiceEndpoint: "https://localhost:8090",
			},
		},
		PublicKey: []did.PublicKey{{
			ID:         "did:example:123456789abcdefghi#keys-1",
			Controller: "did:example:123456789abcdefghi",
			Type:       "Secp256k1VerificationKey2018",
			Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")},
			{
				ID:         "did:example:123456789abcdefghi#keys-1",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Ed25519VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         "did:example:123456789abcdefghw#key2",
				Controller: "did:example:123456789abcdefghw",
				Type:       "RsaVerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
		},
	}
}

func getMockDIDPublicKey() *did.Doc {
	return &did.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      "did:peer:123456789abcdefghi#inbox",
		Service: []did.Service{
			{
				ServiceEndpoint: "https://localhost:8090",
			},
		},
		PublicKey: []did.PublicKey{
			{
				ID:         "did:example:123456789abcdefghi#keys-1",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Secp256k1VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
		},
	}
}

func randomString() string {
	u := uuid.New()
	return u.String()
}

func TestEventsSuccess(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() { require.NoError(t, service.AutoExecuteActionEvent(actionCh)) }()

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for e := range statusCh {
			if e.Type == service.PostState && e.StateID == stateNameRequested {
				done <- struct{}{}
			}
		}
	}()

	id := randomString()
	invite, err := json.Marshal(
		&Invitation{
			Type:  InvitationMsgType,
			ID:    id,
			Label: "test",
		},
	)
	require.NoError(t, err)

	// send invite
	didMsg, err := service.NewDIDCommMsg(invite)
	require.NoError(t, err)

	_, err = svc.HandleInbound(didMsg)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestEventsUserError(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
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
				if e.Type == service.PostState && e.StateID == stateNameAbandoned {
					done <- struct{}{}
				}
			}
		}
	}()

	id := randomString()
	connRec := &ConnectionRecord{ConnectionID: randomString(), ThreadID: id,
		Namespace: findNameSpace(RequestMsgType), State: (&null{}).Name()}

	err = svc.connectionStore.saveNewConnectionRecord(connRec)
	require.NoError(t, err)

	_, err = svc.HandleInbound(generateRequestMsgPayload(t, &protocol.MockProvider{}, id))
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestEventStoreError(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			e.Continue = func() {
				svc.processCallback(&message{Msg: &service.DIDCommMsg{Header: &service.Header{}}})
			}
			e.Continue()
		}
	}()

	_, err = svc.HandleInbound(generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString()))
	require.NoError(t, err)
}

func TestEventProcessCallback(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	msg := &message{
		ThreadID: threadIDValue,
		Msg:      &service.DIDCommMsg{Header: &service.Header{Type: AckMsgType}},
	}

	err = svc.handle(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid state name: invalid state name ")

	err = svc.abandon(msg.ThreadID, msg.Msg, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to update the state to abandoned")
}

func validateState(t *testing.T, svc *Service, id, namespace, expected string) {
	nsThid, err := createNSKey(namespace, id)
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

	msg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	// fetch current state error
	mockStore := &mockStore{get: func(s string) (bytes []byte, e error) {
		return nil, errors.New("error")
	}}
	svc.connectionStore = NewConnectionRecorder(mockStore, nil)
	_, err = svc.HandleInbound(generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString()))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot fetch state from store")

	// invalid message type
	msg.Header.Type = "invalid"
	transientStore, err := mockstorage.NewMockStoreProvider().OpenStore(DIDExchange)
	require.NoError(t, err)

	svc.connectionStore = NewConnectionRecorder(transientStore, nil)

	_, err = svc.HandleInbound(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unrecognized msgType: invalid")

	// test handle - invalid state name
	msg.Header.Type = ResponseMsgType
	message := &message{Msg: msg, ThreadID: randomString()}
	err = svc.handle(message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid state name:")

	// invalid state name
	message.NextStateName = stateNameInvited
	message.ConnRecord = &ConnectionRecord{ConnectionID: "abc"}
	err = svc.handle(message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to execute state invited")
}

func TestHandleOutbound(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	err = svc.HandleOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestConnectionRecord(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	conn, err := svc.connectionRecord(generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString()))
	require.NoError(t, err)
	require.NotNil(t, conn)

	// invalid type
	requestBytes, err := json.Marshal(&Request{
		Type: "invalid-type",
	})
	require.NoError(t, err)
	msg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	_, err = svc.connectionRecord(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid message type")
}

func TestInvitationRecord(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	requestBytes, err := json.Marshal(&Request{
		Type: InvitationMsgType,
		ID:   "id",
	})
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	conn, err := svc.invitationMsgRecord(msg)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// invalid thread id
	requestBytes, err = json.Marshal(&Request{
		Type: "invalid-type",
	})
	require.NoError(t, err)
	msg, err = service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	_, err = svc.invitationMsgRecord(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threadID not found")

	// db error
	svc.connectionStore = NewConnectionRecorder(
		&mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("db error")}, nil)

	requestBytes, err = json.Marshal(&Request{
		Type: InvitationMsgType,
		ID:   "id",
		Connection: &Connection{
			DID: "xyz",
		},
	})
	require.NoError(t, err)

	msg, err = service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	_, err = svc.invitationMsgRecord(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "save connection record")
}

func TestRequestRecord(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	conn, err := svc.requestMsgRecord(generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString()))
	require.NoError(t, err)
	require.NotNil(t, conn)

	// db error
	svc.connectionStore = NewConnectionRecorder(
		&mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("db error")}, nil)

	_, err = svc.requestMsgRecord(generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString()))
	require.Error(t, err)
	require.Contains(t, err.Error(), "save connection record")
}

func TestEventsSuccessWithAsync(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			prop, ok := e.Properties.(event)
			if !ok {
				require.Fail(t, "Failed to cast the event properties to service.Event")
			}

			require.NoError(t, svc.AcceptExchangeRequest(prop.ConnectionID()))
		}
	}()

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for e := range statusCh {
			if e.Type == service.PostState && e.StateID == stateNameRequested {
				done <- struct{}{}
			}
		}
	}()

	_, err = svc.HandleInbound(generateRequestMsgPayload(t, &protocol.MockProvider{}, randomString()))
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestEventTransientData(t *testing.T) {
	t.Run("event transient data - success", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
		require.NoError(t, err)

		connID := generateRandomID()

		msg := &message{
			ConnRecord: &ConnectionRecord{ConnectionID: connID},
		}
		err = svc.storeEventTransientData(msg)
		require.NoError(t, err)

		retrievedMsg, err := svc.getEventTransientData(connID)
		require.NoError(t, err)
		require.Equal(t, msg, retrievedMsg)
	})

	t.Run("event transient data - data not found", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
		require.NoError(t, err)

		err = svc.AcceptExchangeRequest(generateRandomID())
		require.Error(t, err)
		require.Contains(t, err.Error(), "accept exchange request : get transient data : data not found")
	})

	t.Run("event transient data - invalid data", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
		require.NoError(t, err)

		connID := generateRandomID()

		err = svc.connectionStore.transientStore.Put(eventTransientDataKey(connID), []byte("invalid data"))
		require.NoError(t, err)

		_, err = svc.getEventTransientData(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get transient data : invalid character")
	})
}

func TestNextState(t *testing.T) {
	t.Run("empty thread ID", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
		require.NoError(t, err)

		_, err = svc.nextState(RequestMsgType, "")
		require.EqualError(t, err, "unable to compute hash, empty bytes")
	})

	t.Run("valid inputs", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
		require.NoError(t, err)

		s, errState := svc.nextState(RequestMsgType, generateRandomID())
		require.NoError(t, errState)
		require.Equal(t, stateNameRequested, s.Name())
	})
}

func TestFetchConnectionRecord(t *testing.T) {
	t.Run("fetch connection record - invalid payload", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{}, &protocol.MockProvider{})
		require.NoError(t, err)

		_, err = svc.fetchConnectionRecord("", []byte(""))
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})

	t.Run("fetch connection record - no thread id", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
		require.NoError(t, err)

		requestBytes, err := json.Marshal(&Request{
			Type: ResponseMsgType,
			ID:   generateRandomID(),
		})
		require.NoError(t, err)

		_, err = svc.fetchConnectionRecord(theirNSPrefix, requestBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to compute hash, empty bytes")
	})

	t.Run("fetch connection record - valid input", func(t *testing.T) {
		svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
		require.NoError(t, err)

		requestBytes, err := json.Marshal(&Response{
			Type:   ResponseMsgType,
			ID:     generateRandomID(),
			Thread: &decorator.Thread{ID: generateRandomID()},
		})
		require.NoError(t, err)

		_, err = svc.fetchConnectionRecord(theirNSPrefix, requestBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get connectionID by namespaced threadID: data not found")
	})
}

func generateRequestMsgPayload(t *testing.T, prov provider, id string) *service.DIDCommMsg {
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
	newDidDoc, err := ctx.didCreator.Create(testMethod)
	require.NoError(t, err)

	requestBytes, err := json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   id,
		Connection: &Connection{
			DID:    "xyz",
			DIDDoc: newDidDoc,
		},
	})
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	return didMsg
}
