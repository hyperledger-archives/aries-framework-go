/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockdid "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdr/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const testMethod = "peer"

func TestService_Name(t *testing.T) {
	prov, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})

	require.Equal(t, DIDExchange, prov.Name())
	require.NoError(t, err)
}

// did-exchange flow with role Inviter
func TestService_Handle_Inviter(t *testing.T) {
	prov := protocol.MockProvider{}
	pubKey, privKey := generateKeyPair()
	ctx := &context{outboundDispatcher: prov.OutboundDispatcher(),
		didCreator: &mockdid.MockDIDCreator{Doc: createDIDDocWithKey(pubKey)},
		signer:     &mockSigner{privateKey: privKey}}
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
				DID:    "B.did@B:A",
				DIDDoc: newDidDoc,
			},
		})
	require.NoError(t, err)
	msg, err := service.NewDIDCommMsg(payloadBytes)
	require.NoError(t, err)
	err = s.HandleInbound(msg)
	require.NoError(t, err)

	select {
	case <-respondedFlag:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event responded")
	}
	// Alice automatically sends exchange Response to Bob
	// Bob replies with an ACK
	// validateState(t, s, thid, (&responded{}).Name())
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
	err = s.HandleInbound(didMsg)
	require.NoError(t, err)

	select {
	case <-completedFlag:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event complete")
	}
	validateState(t, s, thid, findNameSpace(AckMsgType), (&completed{}).Name())
}

func msgEventListener(t *testing.T, statusCh chan service.StateMsg, respondedFlag, completedFlag chan struct{}) {
	type event interface {
		// connection ID
		ConnectionID() string

		// invitation ID
		InvitationID() string
	}
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
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
		didCreator: &mockdid.MockDIDCreator{Doc: createDIDDocWithKey(pubKey)},
		signer:     &mockSigner{privateKey: privKey}}
	newDidDoc, err := ctx.didCreator.Create(testMethod)
	require.NoError(t, err)

	s, err := New(&mockdid.MockDIDCreator{Doc: createDIDDocWithKey(pubKey)}, &protocol.MockProvider{StoreProvider: store})
	require.NoError(t, err)
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
	err = s.HandleInbound(didMsg)
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
	err = s.HandleInbound(didMsg)
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
	t.Run("must not start with Response msg", func(t *testing.T) {
		ctx := &context{outboundDispatcher: newMockOutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		mockStore, err := mockstorage.NewMockStoreProvider().OpenStore(DIDExchange)
		require.NoError(t, err)
		s := &Service{ctx: ctx, store: mockStore}
		response, err := json.Marshal(
			&Response{
				Type: ResponseMsgType,
				ID:   randomString(),
			},
		)
		require.NoError(t, err)
		err = s.HandleInbound(&service.DIDCommMsg{Payload: response})
		require.Error(t, err)
	})
	t.Run("must not start with ACK msg", func(t *testing.T) {
		ctx := &context{outboundDispatcher: newMockOutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		mockStore, err := mockstorage.NewMockStoreProvider().OpenStore(DIDExchange)
		require.NoError(t, err)
		s := &Service{ctx: ctx, store: mockStore}
		ack, err := json.Marshal(
			&model.Ack{
				Type: AckMsgType,
				ID:   randomString(),
			},
		)
		require.NoError(t, err)
		err = s.HandleInbound(&service.DIDCommMsg{Payload: ack})
		require.Error(t, err)
	})
	t.Run("must not transition to same state", func(t *testing.T) {
		prov := protocol.MockProvider{}
		pubKey, _ := generateKeyPair()
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: createDIDDocWithKey(pubKey)}}
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
		respondedFlag := make(chan bool)
		go func() {
			for e := range statusCh {
				if e.Type == service.PostState {
					// receive the events
					if e.StateID == "responded" {
						respondedFlag <- true
					}
				}
			}
		}()
		go func() { require.NoError(t, service.AutoExecuteActionEvent(actionCh)) }()

		thid := randomString()
		request, err := json.Marshal(
			&Request{
				Type:  RequestMsgType,
				ID:    thid,
				Label: "test",
				Connection: &Connection{
					DID:    newDidDoc.ID,
					DIDDoc: newDidDoc,
				},
			},
		)
		require.NoError(t, err)
		didMsg, err := service.NewDIDCommMsg(request)
		require.NoError(t, err)
		err = s.HandleInbound(didMsg)
		require.NoError(t, err)

		select {
		case <-respondedFlag:
		case <-time.After(2 * time.Second):
			require.Fail(t, "didn't receive post event responded")
		}
		// state machine has automatically transitioned to responded state
		validateState(t, s, thid, findNameSpace(RequestMsgType), (&responded{}).Name())
		// therefore cannot transition Responded state
		response, err := json.Marshal(
			&Response{
				Type:   ResponseMsgType,
				ID:     randomString(),
				Thread: &decorator.Thread{ID: thid},
			},
		)
		require.NoError(t, err)
		didMsg, err = service.NewDIDCommMsg(response)
		require.NoError(t, err)
		err = s.HandleInbound(didMsg)
		require.Error(t, err)
	})
	t.Run("error when updating store on first state transition", func(t *testing.T) {
		ctx := &context{outboundDispatcher: newMockOutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		s := &Service{
			ctx: ctx,
			store: &mockStore{
				get: func(string) ([]byte, error) {
					return nil, storage.ErrDataNotFound
				},
				put: func(string, []byte) error {
					return errors.New("test")
				},
			},
		}
		request, err := json.Marshal(
			&Request{
				Type:  RequestMsgType,
				ID:    randomString(),
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.HandleInbound(&service.DIDCommMsg{Payload: request})
		require.Error(t, err)
	})
	t.Run("error when updating store on followup state transition", func(t *testing.T) {
		counter := 0
		ctx := &context{outboundDispatcher: newMockOutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		s := &Service{
			ctx: ctx,
			store: &mockStore{
				get: func(string) ([]byte, error) {
					return nil, storage.ErrDataNotFound
				},
				put: func(string, []byte) error {
					counter++
					if counter > 1 {
						return errors.New("test")
					}
					return nil
				},
			},
		}
		request, err := json.Marshal(
			&Request{
				Type:  RequestMsgType,
				ID:    randomString(),
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.HandleInbound(&service.DIDCommMsg{Payload: request})
		require.Error(t, err)
	})

	t.Run("error on invalid msg type", func(t *testing.T) {
		ctx := &context{outboundDispatcher: newMockOutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		mockStore, err := mockstorage.NewMockStoreProvider().OpenStore(DIDExchange)
		require.NoError(t, err)
		s := &Service{ctx: ctx, store: mockStore}
		request, err := json.Marshal(
			&Request{
				Type:  "INVALID",
				ID:    randomString(),
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.HandleInbound(&service.DIDCommMsg{Payload: request})
		require.Error(t, err)
	})
}

func TestService_Accept(t *testing.T) {
	dbstore, err := mockstorage.NewMockStoreProvider().OpenStore(DIDExchange)
	require.NoError(t, err)

	ctx := context{outboundDispatcher: newMockOutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
	s := &Service{ctx: &ctx, store: dbstore}

	resp := s.Accept("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation")
	require.Equal(t, true, resp)

	resp = s.Accept("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request")
	require.Equal(t, true, resp)

	resp = s.Accept("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response")
	require.Equal(t, true, resp)

	resp = s.Accept("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/ack")
	require.Equal(t, true, resp)

	resp = s.Accept("unsupported msg type")
	require.Equal(t, false, resp)
}

func TestService_threadID(t *testing.T) {
	t.Run("returns new thid for ", func(t *testing.T) {
		thid, err := threadID(&service.DIDCommMsg{Header: &service.Header{Type: InvitationMsgType}})
		require.NoError(t, err)
		require.NotNil(t, thid)
	})
	t.Run("returns unmarshall error", func(t *testing.T) {
		thid, err := threadID(&service.DIDCommMsg{Header: &service.Header{Type: RequestMsgType}})
		require.Error(t, err)
		require.Equal(t, "", thid)
	})
}

func TestService_currentState(t *testing.T) {
	t.Run("null state if not found in store", func(t *testing.T) {
		svc := &Service{
			connectionStore: NewConnectionRecorder(&mockStore{
				get: func(string) ([]byte, error) { return nil, storage.ErrDataNotFound },
			}),
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
			}),
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
			}),
		}
		thid, err := createNSKey(theirNSPrefix, "ignored")
		require.NoError(t, err)
		_, err = svc.currentState(thid)
		require.Error(t, err)
	})
}

func TestService_update(t *testing.T) {
	const thid = "123"
	const ConnID = "123456"
	s := &requested{}
	data := make(map[string][]byte)
	connRec := &ConnectionRecord{ThreadID: thid, ConnectionID: ConnID, State: s.Name(),
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
		}),
	}

	require.NoError(t, svc.update(RequestMsgType, connRec))
	cr := &ConnectionRecord{}
	err = json.Unmarshal(bytes, cr)
	require.NoError(t, err)
	require.Equal(t, cr, connRec)
}

func newMockOutboundDispatcher() dispatcher.Outbound {
	return (&protocol.MockProvider{}).OutboundDispatcher()
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

func getMockDID() *did.Doc {
	return &did.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      "did:example:123456789abcdefghi#inbox",
		Service: []did.Service{{
			ServiceEndpoint: "https://localhost:8090",
		}},
		PublicKey: []did.PublicKey{{
			ID:         "did:example:123456789abcdefghi#keys-1",
			Controller: "did:example:123456789abcdefghi",
			Type:       "Secp256k1VerificationKey2018",
			Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")},
			{ID: "did:example:123456789abcdefghi#keys-1",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Ed25519VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")},
			{ID: "did:example:123456789abcdefghw#key2",
				Controller: "did:example:123456789abcdefghw",
				Type:       "RsaVerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")},
		},
	}
}
func getMockDIDPublicKey() *did.Doc {
	return &did.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      "did:example:123456789abcdefghi#inbox",
		Service: []did.Service{{
			ServiceEndpoint: "https://localhost:8090",
		}},
		PublicKey: []did.PublicKey{{
			ID:         "did:example:123456789abcdefghi#keys-1",
			Controller: "did:example:123456789abcdefghi",
			Type:       "Secp256k1VerificationKey2018",
			Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")},
		},
	}
}

func randomString() string {
	u := uuid.New()
	return u.String()
}

func TestEventsSuccess(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
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

	err = svc.HandleInbound(didMsg)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestEventsUserError(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
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
	requestBytes, err := json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   id,
		Connection: &Connection{
			DID: "xyz",
		},
	})
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	err = svc.HandleInbound(didMsg)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestEventStoreError(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			e.Continue = func(...interface{}) {
				svc.processCallback(&message{Msg: &service.DIDCommMsg{Header: &service.Header{}}})
			}
			e.Continue()
		}
	}()

	id := randomString()

	request, err := json.Marshal(
		&Request{
			Type:  RequestMsgType,
			ID:    id,
			Label: "test",
			Connection: &Connection{
				DID: "xyz",
			},
		},
	)
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)

	err = svc.HandleInbound(didMsg)
	require.NoError(t, err)
}

func TestEventProcessCallback(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
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

func TestUpdateState(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)
	svc.store = &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("db error")}
	svc.connectionStore = NewConnectionRecorder(svc.store)
	connRec := &ConnectionRecord{State: (&abandoned{}).Name()}
	err = svc.update(RequestMsgType, connRec)
	require.Error(t, err)
	require.Contains(t, err.Error(), "db error")
}

func TestService_No_Execution(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)
	require.EqualError(t, svc.HandleInbound(&service.DIDCommMsg{
		Header: &service.Header{Type: ResponseMsgType},
	}), "no clients are registered to handle the message")
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
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)
	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	// fetch current state error
	mockStore := &mockStore{get: func(s string) (bytes []byte, e error) {
		return nil, errors.New("error")
	}}
	svc.store = mockStore
	svc.connectionStore = NewConnectionRecorder(mockStore)
	err = svc.HandleInbound(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot fetch state from store")

	// invalid message type
	msg.Header.Type = "invalid"
	svc.store, err = mockstorage.NewMockStoreProvider().OpenStore(DIDExchange)
	svc.connectionStore = NewConnectionRecorder(svc.store)
	require.NoError(t, err)
	err = svc.HandleInbound(msg)
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
	message.connRecord = &ConnectionRecord{ConnectionID: "abc"}
	err = svc.handle(message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to execute state invited")
}

func TestMsgEventProtocolFailure(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)

	actionCh := make(chan service.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			e.Stop(errors.New("user error"))
		}
	}()

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		for e := range statusCh {
			if e.Type == service.PostState && e.StateID == (&abandoned{}).Name() {
				svcErr, ok := e.Properties.(error)
				require.Equal(t, true, ok)
				require.Equal(t, "user error", svcErr.Error())

				done <- struct{}{}
			}
		}
	}()
	id := randomString()
	connRec := &ConnectionRecord{ConnectionID: randomString(), ThreadID: id,
		Namespace: findNameSpace(RequestMsgType), State: (&null{}).Name()}

	err = svc.connectionStore.saveNewConnectionRecord(connRec)
	require.NoError(t, err)
	requestBytes, err := json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   id,
		Connection: &Connection{
			DID: "xyz",
		},
	})
	require.NoError(t, err)
	msg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)
	err = svc.HandleInbound(msg)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestHandleOutbound(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)

	err = svc.HandleOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestConnectionRecord(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)

	requestBytes, err := json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   "id",
		Connection: &Connection{
			DID: "xyz",
		},
	})
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	conn, err := svc.connectionRecord(msg)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// invalid type
	requestBytes, err = json.Marshal(&Request{
		Type: "invalid-type",
	})
	require.NoError(t, err)
	msg, err = service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	_, err = svc.connectionRecord(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid message type")
}

func TestInvitationRecord(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
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
	svc.store = &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("db error")}
	svc.connectionStore = NewConnectionRecorder(svc.store)

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
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)

	requestBytes, err := json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   "id",
		Connection: &Connection{
			DID: "xyz",
		},
	})
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	conn, err := svc.requestMsgRecord(msg)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// db error
	svc.store = &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("db error")}
	svc.connectionStore = NewConnectionRecorder(svc.store)

	requestBytes, err = json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   "id",
		Connection: &Connection{
			DID: "xyz",
		},
	})
	require.NoError(t, err)

	msg, err = service.NewDIDCommMsg(requestBytes)
	require.NoError(t, err)

	_, err = svc.requestMsgRecord(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "save connection record")
}
