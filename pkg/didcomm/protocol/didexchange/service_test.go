/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"sync"
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
	mockdid "github.com/hyperledger/aries-framework-go/pkg/internal/mock/common/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	invalidThreadID = "invalidThreadID"
	corrupt         = "corrupt"
	handleError     = "handle-error"
	changeID        = "change-id"
)

func TestService_Name(t *testing.T) {
	prov, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})

	require.Equal(t, DIDExchange, prov.Name())
	require.NoError(t, err)
}

// did-exchange flow with role Inviter
func TestService_Handle_Inviter(t *testing.T) {
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)

	s, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
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
			Type:  ConnectionRequest,
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
			Type:   ConnectionAck,
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
	validateState(t, s, thid, (&completed{}).Name())
}

func msgEventListener(t *testing.T, statusCh chan service.StateMsg, respondedFlag, completedFlag chan struct{}) {
	connectionID := ""
	invitationID := ""
	for e := range statusCh {
		require.Equal(t, DIDExchange, e.ProtocolName)
		prop, ok := e.Properties.(Event)
		if !ok {
			require.Fail(t, "Failed to cast the event properties to service.Event")
		}
		// Get the connectionID when it's created
		if e.Type == service.PreState {
			if e.StateID == "requested" {
				connectionID = prop.ConnectionID()
				invitationID = prop.InvitationID()
			}
		}
		if e.Type == service.PostState {
			// receive the events
			if e.StateID == "completed" {
				// validate connectionID received during state transition with original connectionID
				require.Equal(t, connectionID, prop.ConnectionID())
				require.Equal(t, invitationID, prop.InvitationID())
				close(completedFlag)
			}
			if e.StateID == "responded" {
				// validate connectionID received during state transition with original connectionID
				require.Equal(t, connectionID, prop.ConnectionID())
				require.Equal(t, invitationID, prop.InvitationID())
				close(respondedFlag)
			}
		}
	}
}

// did-exchange flow with role Invitee
func TestService_Handle_Invitee(t *testing.T) {
	data := make(map[string]string)
	// using this mockStore as a hack in order to obtain the auto-generated thid after
	// automatically sending the request back to Bob
	var lock sync.RWMutex
	store := &mockStore{
		put: func(s string, bytes []byte) error {
			lock.Lock()
			defer lock.Unlock()
			data[s] = string(bytes)
			return nil
		},
		get: func(s string) (bytes []byte, e error) {
			lock.RLock()
			defer lock.RUnlock()
			if state, found := data[s]; found {
				return []byte(state), nil
			}
			return nil, storage.ErrDataNotFound
		},
	}
	prov := protocol.MockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
	newDidDoc, err := ctx.didCreator.CreateDID()
	require.NoError(t, err)

	s, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{CustomStore: store})
	require.NoError(t, err)
	actionCh := make(chan service.DIDCommAction, 10)
	err = s.RegisterActionEvent(actionCh)
	require.NoError(t, err)
	statusCh := make(chan service.StateMsg, 10)
	err = s.RegisterMsgEvent(statusCh)
	require.NoError(t, err)
	done := make(chan bool)
	go func() {
		for e := range statusCh {
			if e.Type == service.PostState {
				// receive the events
				if e.StateID == "completed" {
					done <- true
				}
			}
		}
	}()
	go func() { require.NoError(t, service.AutoExecuteActionEvent(actionCh)) }()

	// Alice receives an invitation from Bob
	payloadBytes, err := json.Marshal(
		&Invitation{
			Type:  ConnectionInvite,
			ID:    randomString(),
			Label: "Bob",
		},
	)
	require.NoError(t, err)
	didMsg, err := service.NewDIDCommMsg(payloadBytes)
	require.NoError(t, err)
	err = s.HandleInbound(didMsg)
	require.NoError(t, err)

	// Alice automatically sends a Request to Bob and is now in REQUESTED state.
	connRecord := &ConnectionRecord{}
	for _, v := range data {
		currentData := v
		err = json.Unmarshal([]byte(currentData), connRecord)
		if err == nil && (&requested{}).Name() == connRecord.State {
			break
		}
	}
	require.Equal(t, (&requested{}).Name(), connRecord.State)

	connection := &Connection{
		DID:    newDidDoc.ID,
		DIDDoc: newDidDoc,
	}

	connectionSignature, err := prepareConnectionSignature(connection)
	require.NoError(t, err)

	// Bob replies with a Response
	payloadBytes, err = json.Marshal(
		&Response{
			Type:                ConnectionResponse,
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
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "didn't receive post event complete")
	}
	validateState(t, s, connRecord.ThreadID, (&completed{}).Name())
}

func TestService_Handle_EdgeCases(t *testing.T) {
	t.Run("must not start with Response msg", func(t *testing.T) {
		ctx := context{outboundDispatcher: newMockOutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		mockStore, err := mockstorage.NewMockStoreProvider().OpenStore(DIDExchange)
		require.NoError(t, err)
		s := &Service{ctx: ctx, store: mockStore}
		response, err := json.Marshal(
			&Response{
				Type: ConnectionResponse,
				ID:   randomString(),
			},
		)
		require.NoError(t, err)
		err = s.HandleInbound(&service.DIDCommMsg{Payload: response})
		require.Error(t, err)
	})
	t.Run("must not start with ACK msg", func(t *testing.T) {
		ctx := context{outboundDispatcher: newMockOutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		mockStore, err := mockstorage.NewMockStoreProvider().OpenStore(DIDExchange)
		require.NoError(t, err)
		s := &Service{ctx: ctx, store: mockStore}
		ack, err := json.Marshal(
			&model.Ack{
				Type: ConnectionAck,
				ID:   randomString(),
			},
		)
		require.NoError(t, err)
		err = s.HandleInbound(&service.DIDCommMsg{Payload: ack})
		require.Error(t, err)
	})
	t.Run("must not transition to same state", func(t *testing.T) {
		prov := protocol.MockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(),
			didCreator: &mockdid.MockDIDCreator{Doc: getMockDID()}}
		newDidDoc, err := ctx.didCreator.CreateDID()
		require.NoError(t, err)

		s, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
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
				Type:  ConnectionRequest,
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
		validateState(t, s, thid, (&responded{}).Name())
		// therefore cannot transition Responded state
		response, err := json.Marshal(
			&Response{
				Type:   ConnectionResponse,
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
		ctx := context{outboundDispatcher: newMockOutboundDispatcher(),
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
				Type:  ConnectionRequest,
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
		ctx := context{outboundDispatcher: newMockOutboundDispatcher(),
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
				Type:  ConnectionRequest,
				ID:    randomString(),
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.HandleInbound(&service.DIDCommMsg{Payload: request})
		require.Error(t, err)
	})

	t.Run("error on invalid msg type", func(t *testing.T) {
		ctx := context{outboundDispatcher: newMockOutboundDispatcher(),
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
	s := &Service{ctx: ctx, store: dbstore}

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
		thid, err := threadID(&service.DIDCommMsg{Header: &service.Header{Type: ConnectionInvite}})
		require.NoError(t, err)
		require.NotNil(t, thid)
	})
	t.Run("returns unmarshall error", func(t *testing.T) {
		thid, err := threadID(&service.DIDCommMsg{Header: &service.Header{Type: ConnectionRequest}})
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
		s, err := svc.currentState("ignored")
		require.NoError(t, err)
		require.Equal(t, (&null{}).Name(), s.Name())
	})
	t.Run("returns state from store", func(t *testing.T) {
		expected := &requested{}
		connRecBytes, err := json.Marshal(&ConnectionRecord{State: expected.Name()})
		require.NoError(t, err)
		svc := &Service{
			connectionStore: NewConnectionRecorder(&mockStore{
				get: func(string) ([]byte, error) { return connRecBytes, nil },
			}),
		}
		actual, err := svc.currentState("ignored")
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
		_, err := svc.currentState("ignored")
		require.Error(t, err)
	})
}

func TestService_update(t *testing.T) {
	const thid = "123"
	const ConnID = "123456"
	s := &requested{}
	data := make(map[string][]byte)
	connRec := &ConnectionRecord{ThreadID: thid, ConnectionID: ConnID, State: s.Name()}
	bytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	svc := &Service{
		store: &mockStore{
			put: func(k string, v []byte) error {
				data[k] = bytes
				return nil
			},
			get: func(k string) ([]byte, error) {
				return bytes, nil
			},
		},
	}
	require.NoError(t, svc.update("123", s))
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

type payload struct {
	ID string `json:"@id"`
}

func TestService_Events(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)
	done := make(chan bool)

	startConsumer(t, svc, done)

	validateSuccessCase(t, svc)

	validateUserError(t, svc)

	validateStoreError(t, svc)

	validateHandleError(t, svc)

	validateStoreDataCorruptionError(t, svc)

	// signal the end of tests (to make sure all the message types are processed)
	func() {
		id := "done"
		request, err := json.Marshal(
			&Request{
				Type: ConnectionRequest,
				ID:   id,
			},
		)
		require.NoError(t, err)
		didMsg, err := service.NewDIDCommMsg(request)
		require.NoError(t, err)
		err = svc.HandleInbound(didMsg)
		require.NoError(t, err)
	}()

	select {
	case res := <-done:
		require.True(t, res)
	case <-time.After(15 * time.Second):
		require.Fail(t, "tests are not validated")
	}

	validateStatusEventAction(t, svc, time.Millisecond*50)
}

func startConsumer(t *testing.T, svc *Service, done chan bool) {
	actionCh := make(chan service.DIDCommAction, 10)
	err := svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			require.Equal(t, DIDExchange, e.ProtocolName)
			// assigned to var as lint fails with : Using a reference for the variable on range scope (scopelint)
			msg := e
			// receive the events
			switch e.Message.Header.Type {
			// receive the event on ConnectionRequest message type
			case ConnectionRequest:
				handleConnectionRequestEvents(t, svc, &msg, done)
			// receive the event on ConnectionResponse message type
			case ConnectionResponse:
				handleConnectionResponseEvents(t, svc, &msg)
			// receive the event on ConnectionAck message type
			case ConnectionAck:
				handleConnectionAckEvents(t, svc, &msg)
			}
		}
	}()

	statusCh := make(chan service.StateMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)
	go func() {
		for e := range statusCh {
			if e.Type == service.PreState {
				// receive the events
				if e.Msg.Header.Type == ConnectionRequest {
					writeToDB(t, svc, e.Msg)
				}
			}
		}
	}()
}

func handleConnectionRequestEvents(t *testing.T, svc *Service, e *service.DIDCommAction, done chan bool) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionRequest, e.Message.Header.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == "done" {
		done <- true
		return
	}
	err = func(e *service.DIDCommAction) error {
		errUnmarshal := json.Unmarshal(e.Message.Payload, &pl)
		require.NoError(t, errUnmarshal)

		if pl.ID == invalidThreadID {
			return errors.New("invalid id")
		}

		return nil
	}(e)

	// invoke callback
	if err != nil {
		e.Stop(err)
	} else {
		e.Continue()
	}

	if pl.ID == invalidThreadID {
		// no state change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "null", s.Name())
	} else {
		require.Fail(t, "handleConnectionRequestEvents tests are not validated")
	}
}

func handleConnectionResponseEvents(t *testing.T, svc *Service, e *service.DIDCommAction) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionResponse, e.Message.Header.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == changeID {
		e.Continue = func() {
			svc.processCallback("invalid-id", nil)
		}
	}

	if pl.ID == handleError {
		jsonDoc, err := json.Marshal(&message{
			NextStateName: "invalid",
		})
		require.NoError(t, err)

		id := generateRandomID()
		err = svc.store.Put(id, jsonDoc)
		require.NoError(t, err)

		e.Continue = func() {
			svc.processCallback(id, nil)
		}
	}

	// invoke callback
	e.Continue()
	switch pl.ID {
	case changeID:
		// no state change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "requested", s.Name())
	case handleError:
		// no s change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "requested", s.Name())
	default:
		require.Fail(t, "handleConnectionResponseEvents tests are not validated")
	}
}

func handleConnectionAckEvents(t *testing.T, svc *Service, e *service.DIDCommAction) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionAck, e.Message.Header.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == corrupt {
		id := generateRandomID()
		err := svc.store.Put(id, []byte("invalid json"))
		require.NoError(t, err)

		e.Continue = func() {
			svc.processCallback(id, nil)
		}
	}

	// invoke callback
	e.Continue()
	if pl.ID == corrupt {
		// no state change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "responded", s.Name())
	} else {
		require.Fail(t, "handleConnectionAckEvents tests are not validated")
	}
}

func writeToDB(t *testing.T, svc *Service, e *service.DIDCommMsg) {
	require.NotEmpty(t, e)

	pl := payload{}
	err := json.Unmarshal(e.Payload, &pl)
	require.NoError(t, err)
	require.NoError(t, svc.store.Put("status-event"+pl.ID, []byte("status_event")))
}

func validateSuccessCase(t *testing.T, svc *Service) {
	id := "valid-thread-id"
	// verify the state before invite
	s, err := svc.currentState(id)
	require.NoError(t, err)
	require.Equal(t, "null", s.Name())

	invite, err := json.Marshal(
		&Invitation{
			Type:  ConnectionInvite,
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
}

func validateUserError(t *testing.T, svc *Service) {
	id := invalidThreadID

	// verify the state before connection request message
	s, err := svc.currentState(id)
	require.NoError(t, err)
	require.Equal(t, "null", s.Name())

	request, err := json.Marshal(
		&Request{
			Type:  ConnectionRequest,
			ID:    id,
			Label: "test",
		},
	)
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)
	err = svc.HandleInbound(didMsg)
	require.NoError(t, err)
}

func validateStoreError(t *testing.T, svc *Service) {
	id := changeID

	// update the state to requested for this thread ID (to bypass the validations for ConnectionResponse message type)
	err := svc.update(id, &requested{})
	require.NoError(t, err)

	// verify the state before connection response message
	s, err := svc.currentState(id)
	require.NoError(t, err)
	require.Equal(t, "requested", s.Name())

	request, err := json.Marshal(
		&Request{
			Type:  ConnectionResponse,
			ID:    id,
			Label: "test",
		},
	)
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)
	err = svc.HandleInbound(didMsg)
	require.NoError(t, err)
}

func validateStoreDataCorruptionError(t *testing.T, svc *Service) {
	id := corrupt

	// update the state to responded for this thread ID (to bypass the validations for ConnectionAck message type)
	err := svc.update(id, &responded{})
	require.NoError(t, err)

	// verify the s
	s, err := svc.currentState(id)
	require.NoError(t, err)
	require.Equal(t, "responded", s.Name())

	request, err := json.Marshal(
		&Request{
			Type:  ConnectionAck,
			ID:    id,
			Label: "test",
		},
	)
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)
	err = svc.HandleInbound(didMsg)
	require.NoError(t, err)
}

func validateHandleError(t *testing.T, svc *Service) {
	id := handleError

	// update the state to requested for this thread ID (to bypass the validations for ConnectionResponse message type)
	err := svc.update(id, &requested{})
	require.NoError(t, err)

	// verify the s before invite
	s, err := svc.currentState(id)
	require.NoError(t, err)
	require.Equal(t, "requested", s.Name())

	request, err := json.Marshal(
		&Request{
			Type:  ConnectionResponse,
			ID:    id,
			Label: "test",
		},
	)
	require.NoError(t, err)

	didMsg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)
	err = svc.HandleInbound(didMsg)
	require.NoError(t, err)
}

func validateStatusEventAction(t *testing.T, svc *Service, duration time.Duration) {
	timeout := time.After(duration)
	for {
		select {
		case <-timeout:
			t.Error("deadline exceeded")
			return
		default:
			val, err := svc.store.Get("status-event" + invalidThreadID)
			if err != nil {
				continue
			}
			require.Equal(t, "status_event", string(val))
			return
		}
	}
}

func TestService_No_Execution(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)
	msg := service.DIDCommMsg{
		Header: &service.Header{Type: ConnectionResponse},
	}

	err = svc.HandleInbound(&msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no clients are registered to handle the message")
}

func validateState(t *testing.T, svc *Service, id, expected string) {
	s, err := svc.currentState(id)
	require.NoError(t, err)
	require.Equal(t, expected, s.Name())
}

func TestServiceErrors(t *testing.T) {
	request, err := json.Marshal(
		&Request{
			Type:  ConnectionResponse,
			ID:    randomString(),
			Label: "test",
		},
	)
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(request)
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
	msg.Header.Type = ConnectionResponse
	message := &message{Msg: msg, ThreadID: randomString()}
	err = svc.handle(message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid state name:")

	// invalid state name
	message.NextStateName = stateNameInvited
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

	// update the state to responded for this thread ID (to bypass the validations for ConnectionAck message type)
	id := randomString()
	err = svc.update(id, &responded{})
	require.NoError(t, err)

	// verify the current state
	s, err := svc.currentState(id)
	require.NoError(t, err)
	require.Equal(t, (&responded{}).Name(), s.Name())

	request, err := json.Marshal(
		&Request{
			Type:  ConnectionAck,
			ID:    id,
			Label: "test",
		},
	)
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)

	err = svc.HandleInbound(msg)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		require.Fail(t, "tests are not validated")
	}

	s, err = svc.currentState(id)
	require.NoError(t, err)
	require.Equal(t, (&abandoned{}).Name(), s.Name())
}

func TestHandleOutbound(t *testing.T) {
	svc, err := New(&mockdid.MockDIDCreator{Doc: getMockDID()}, &protocol.MockProvider{})
	require.NoError(t, err)

	err = svc.HandleOutbound(&service.DIDCommMsg{}, &service.Destination{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}
