/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

const (
	invalidThreadID = "invalidThreadID"
	corrupt         = "corrupt"
	handleError     = "handle-error"
	changeID        = "change-id"
)

func TestGenerateInviteWithPublicDID(t *testing.T) {
	invite, err := GenerateInviteWithPublicDID(&Invitation{
		ID:    "12345678900987654321",
		Label: "Alice",
		DID:   "did:example:ZadolSRQkehfo",
	})

	require.NoError(t, err)
	require.NotEmpty(t, invite)

	invite, err = GenerateInviteWithPublicDID(&Invitation{
		ID:    "12345678900987654321",
		Label: "Alice",
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithPublicDID(&Invitation{
		Label: "Alice",
		DID:   "did:example:ZadolSRQkehfo",
	})
	require.Error(t, err)
	require.Empty(t, invite)
}

func TestGenerateInviteWithKeyAndEndpoint(t *testing.T) {
	invite, err := GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:              "12345678900987654321",
		Label:           "Alice",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		Label:           "Alice",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:            "12345678900987654321",
		Label:         "Alice",
		RecipientKeys: []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		RoutingKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:              "12345678900987654321",
		Label:           "Alice",
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)
}

func TestService_Name(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	prov := New(dbstore, &mockProvider{})

	require.Equal(t, DIDExchange, prov.Name())
}

// did-exchange flow with role Inviter
func TestService_Handle_Inviter(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	prov := mockProvider{}
	ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didWallet: prov.DIDWallet()}
	newDidDoc, err := ctx.didWallet.CreateDID(didMethod)
	require.NoError(t, err)

	s := New(dbstore, &mockProvider{})
	actionCh := make(chan dispatcher.DIDCommAction, 10)
	err = s.RegisterActionEvent(actionCh)
	require.NoError(t, err)
	go func() { require.NoError(t, AutoExecuteActionEvent(actionCh)) }()

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
	msg := dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	// Alice automatically sends exchange Response to Bob
	// Bob replies with an ACK
	validateState(t, s, thid, (&responded{}).Name(), 100*time.Millisecond)
	payloadBytes, err = json.Marshal(
		&Ack{
			Type:   ConnectionAck,
			ID:     randomString(),
			Status: "OK",
			Thread: &decorator.Thread{ID: thid},
		})
	require.NoError(t, err)
	msg = dispatcher.DIDCommMsg{Type: ConnectionAck, Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)
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

	s := New(store, &mockProvider{})
	actionCh := make(chan dispatcher.DIDCommAction, 10)
	err := s.RegisterActionEvent(actionCh)
	require.NoError(t, err)
	go func() { require.NoError(t, AutoExecuteActionEvent(actionCh)) }()

	// Alice receives an invitation from Bob
	payloadBytes, err := json.Marshal(
		&Invitation{
			Type:  ConnectionInvite,
			ID:    randomString(),
			Label: "Bob",
			DID:   "did:example:bob",
		},
	)
	require.NoError(t, err)
	msg := dispatcher.DIDCommMsg{Type: ConnectionInvite, Outbound: false, Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	// Alice automatically sends a Request to Bob and is now in REQUESTED state.
	var thid string
	var currState string
	for k, v := range data {
		thid = k
		currState = v
		break
	}
	require.NotEmpty(t, thid)
	require.Equal(t, (&requested{}).Name(), currState)

	// Bob replies with a Response
	payloadBytes, err = json.Marshal(
		&Response{
			Type:   ConnectionResponse,
			ID:     randomString(),
			Thread: &decorator.Thread{ID: thid},
		},
	)
	require.NoError(t, err)
	msg = dispatcher.DIDCommMsg{Type: ConnectionResponse, Outbound: false, Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	// Alice automatically sends an ACK to Bob
	// Alice must now be in COMPLETED state
	validateState(t, s, thid, (&completed{}).Name(), 100*time.Millisecond)
}

func TestService_Handle_EdgeCases(t *testing.T) {
	t.Run("must not start with Response msg", func(t *testing.T) {
		ctx := context{outboundDispatcher: newMockOutboundDispatcher()}
		s := &Service{ctx: ctx, store: newMockStore()}
		response, err := json.Marshal(
			&Response{
				Type: ConnectionResponse,
				ID:   randomString(),
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: ConnectionResponse, Payload: response})
		require.Error(t, err)
	})
	t.Run("must not start with ACK msg", func(t *testing.T) {
		ctx := context{outboundDispatcher: newMockOutboundDispatcher()}
		s := &Service{ctx: ctx, store: newMockStore()}
		ack, err := json.Marshal(
			&Ack{
				Type: ConnectionAck,
				ID:   randomString(),
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: ConnectionAck, Payload: ack})
		require.Error(t, err)
	})
	t.Run("must not transition to same state", func(t *testing.T) {
		prov := mockProvider{}
		ctx := context{outboundDispatcher: prov.OutboundDispatcher(), didWallet: prov.DIDWallet()}
		newDidDoc, err := ctx.didWallet.CreateDID(didMethod)
		require.NoError(t, err)

		s := New(newMockStore(), &mockProvider{})
		actionCh := make(chan dispatcher.DIDCommAction, 10)
		err = s.RegisterActionEvent(actionCh)
		require.NoError(t, err)

		go func() { require.NoError(t, AutoExecuteActionEvent(actionCh)) }()

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
		err = s.Handle(dispatcher.DIDCommMsg{Type: ConnectionRequest, Outbound: false, Payload: request})
		require.NoError(t, err)
		// state machine has automatically transitioned to responded state
		validateState(t, s, thid, (&responded{}).Name(), 100*time.Millisecond)
		// therefore cannot transition Responded state
		response, err := json.Marshal(
			&Response{
				Type:   ConnectionResponse,
				ID:     randomString(),
				Thread: &decorator.Thread{ID: thid},
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: ConnectionResponse, Outbound: false, Payload: response})
		require.Error(t, err)
	})
	t.Run("error when updating store on first state transition", func(t *testing.T) {
		ctx := context{outboundDispatcher: newMockOutboundDispatcher()}
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
		err = s.Handle(dispatcher.DIDCommMsg{Type: ConnectionRequest, Outbound: false, Payload: request})
		require.Error(t, err)
	})
	t.Run("error when updating store on followup state transition", func(t *testing.T) {
		counter := 0
		ctx := context{outboundDispatcher: newMockOutboundDispatcher()}
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
		err = s.Handle(dispatcher.DIDCommMsg{Type: ConnectionRequest, Outbound: false, Payload: request})
		require.Error(t, err)
	})

	t.Run("error on invalid msg type", func(t *testing.T) {
		ctx := context{outboundDispatcher: newMockOutboundDispatcher()}
		s := &Service{ctx: ctx, store: newMockStore()}
		request, err := json.Marshal(
			&Request{
				Type:  ConnectionRequest,
				ID:    randomString(),
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: "INVALID", Outbound: false, Payload: request})
		require.Error(t, err)
	})
}

func TestService_Accept(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	ctx := context{outboundDispatcher: newMockOutboundDispatcher()}
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
	t.Run("returns thid contained in msg", func(t *testing.T) {
		const expected = "123456"
		msg := fmt.Sprintf(`{"~thread": {"thid": "%s"}}`, expected)
		actual, err := threadID([]byte(msg))
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})
	t.Run("returns empty thid when msg does not contain thid", func(t *testing.T) {
		const expected = ""
		actual, err := threadID([]byte("{}"))
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})
}

func TestService_currentState(t *testing.T) {
	t.Run("null state if not found in store", func(t *testing.T) {
		svc := &Service{
			store: &mockStore{
				get: func(string) ([]byte, error) { return nil, storage.ErrDataNotFound },
			},
		}
		s, err := svc.currentState("ignored")
		require.NoError(t, err)
		require.Equal(t, (&null{}).Name(), s.Name())
	})
	t.Run("returns state from store", func(t *testing.T) {
		expected := &requested{}
		svc := &Service{
			store: &mockStore{
				get: func(string) ([]byte, error) { return []byte(expected.Name()), nil },
			},
		}
		actual, err := svc.currentState("ignored")
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("forwards generic error from store", func(t *testing.T) {
		svc := &Service{
			store: &mockStore{
				get: func(string) ([]byte, error) {
					return nil, errors.New("test")
				},
			},
		}
		_, err := svc.currentState("ignored")
		require.Error(t, err)
	})
}

func TestService_update(t *testing.T) {
	const thid = "123"
	s := &responded{}
	data := make(map[string][]byte)
	store := &mockStore{
		put: func(k string, v []byte) error {
			data[k] = v
			return nil
		},
	}
	require.NoError(t, (&Service{store: store}).update("123", s))
	require.Equal(t, s.Name(), string(data[thid]))
}

func newMockOutboundDispatcher() dispatcher.Outbound {
	return (&mockProvider{}).OutboundDispatcher()
}

func newMockStore() storage.Store {
	var lock sync.RWMutex
	data := make(map[string][]byte)
	return &mockStore{
		put: func(k string, v []byte) error {
			lock.Lock()
			defer lock.Unlock()
			data[k] = v
			return nil
		},
		get: func(k string) ([]byte, error) {
			lock.RLock()
			defer lock.RUnlock()
			v, found := data[k]
			if !found {
				return nil, storage.ErrDataNotFound
			}
			return v, nil
		},
	}
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

type mockProvider struct {
}

func (p *mockProvider) OutboundDispatcher() dispatcher.Outbound {
	return &mockdispatcher.MockOutbound{}
}

// CryptoWallet returns the pack wallet service
func (p *mockProvider) DIDWallet() wallet.DIDCreator {
	return &mockwallet.CloseableWallet{}
}
func store(t testing.TB) (storage.Store, func()) {
	prov := mockstorage.NewMockStoreProvider()
	dbstore, err := prov.GetStoreHandle()
	require.NoError(t, err)
	return dbstore, func() {
		err := prov.Close()
		require.NoError(t, err)
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
	dbstore, cleanup := store(t)
	defer cleanup()
	prov := &mockProvider{}
	svc := New(dbstore, prov)
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

		msg := dispatcher.DIDCommMsg{
			Type:    ConnectionRequest,
			Payload: request,
		}

		err = svc.Handle(msg)
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
	actionCh := make(chan dispatcher.DIDCommAction, 10)
	err := svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	go func() {
		for e := range actionCh {
			// receive the events
			switch e.Message.Type {
			// receive the event on ConnectionRequest message type
			case ConnectionRequest:
				handleConnectionRequestEvents(t, svc, e, done)
			// receive the event on ConnectionResponse message type
			case ConnectionResponse:
				handleConnectionResponseEvents(t, svc, e)
			// receive the event on ConnectionAck message type
			case ConnectionAck:
				handleConnectionAckEvents(t, svc, e)
			}
		}
	}()

	statusCh := make(chan dispatcher.DIDCommMsg, 10)
	err = svc.RegisterMsgEvent(statusCh)
	require.NoError(t, err)
	go func() {
		for e := range statusCh {
			// receive the events
			if e.Type == ConnectionRequest {
				writeToDB(t, svc, e)
			}
		}
	}()
}

func handleConnectionRequestEvents(t *testing.T, svc *Service, e dispatcher.DIDCommAction, done chan bool) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionRequest, e.Message.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == "done" {
		done <- true
		return
	}
	err = func(e dispatcher.DIDCommAction) error {
		errUnmarshal := json.Unmarshal(e.Message.Payload, &pl)
		require.NoError(t, errUnmarshal)

		if pl.ID == invalidThreadID {
			return errors.New("invalid id")
		}

		return nil
	}(e)

	// invoke callback
	e.Callback(dispatcher.DIDCommCallback{Err: err})

	if pl.ID == invalidThreadID {
		// no state change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "null", s.Name())
	} else {
		require.Fail(t, "handleConnectionRequestEvents tests are not validated")
	}
}

func handleConnectionResponseEvents(t *testing.T, svc *Service, e dispatcher.DIDCommAction) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionResponse, e.Message.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == changeID {
		e.Callback = func(didCommCallback dispatcher.DIDCommCallback) {
			svc.processCallback("invalid-id", didCommCallback)
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

		e.Callback = func(didCommCallback dispatcher.DIDCommCallback) {
			svc.processCallback(id, didCommCallback)
		}
	}

	// invoke callback
	e.Callback(dispatcher.DIDCommCallback{Err: nil})
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

func handleConnectionAckEvents(t *testing.T, svc *Service, e dispatcher.DIDCommAction) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionAck, e.Message.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == corrupt {
		id := generateRandomID()
		err := svc.store.Put(id, []byte("invalid json"))
		require.NoError(t, err)

		e.Callback = func(didCommCallback dispatcher.DIDCommCallback) {
			svc.processCallback(id, didCommCallback)
		}
	}

	// invoke callback
	e.Callback(dispatcher.DIDCommCallback{Err: nil})
	if pl.ID == corrupt {
		// no state change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "responded", s.Name())
	} else {
		require.Fail(t, "handleConnectionAckEvents tests are not validated")
	}
}

func writeToDB(t *testing.T, svc *Service, e dispatcher.DIDCommMsg) {
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
	msg := dispatcher.DIDCommMsg{
		Type:    ConnectionInvite,
		Payload: invite,
	}

	err = svc.Handle(msg)
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

	msg := dispatcher.DIDCommMsg{
		Type:    ConnectionRequest,
		Payload: request,
	}

	err = svc.Handle(msg)
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

	msg := dispatcher.DIDCommMsg{
		Type:    ConnectionResponse,
		Payload: request,
	}

	err = svc.Handle(msg)
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

	msg := dispatcher.DIDCommMsg{
		Type:    ConnectionAck,
		Payload: request,
	}

	err = svc.Handle(msg)
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

	msg := dispatcher.DIDCommMsg{
		Type:    ConnectionResponse,
		Payload: request,
	}

	err = svc.Handle(msg)
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
	dbstore, cleanup := store(t)
	defer cleanup()

	svc := New(dbstore, &mockProvider{})

	msg := dispatcher.DIDCommMsg{
		Type: ConnectionResponse,
	}

	err := svc.Handle(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no clients are registered to handle the message")
}

func validateState(t *testing.T, svc *Service, id, expected string, timeoutDuration time.Duration) {
	actualState := ""
	timeout := time.After(timeoutDuration)
	for {
		select {
		case <-timeout:
			require.Fail(t, fmt.Sprintf("id=%s expectedState=%s actualState=%s", id, expected, actualState))
			return
		default:
			s, err := svc.currentState(id)
			actualState = s.Name()
			if err != nil || expected != s.Name() {
				continue
			}
			return
		}
	}
}

func TestService_ActionEvent(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()

	svc := New(dbstore, &mockProvider{})

	// validate before register
	require.Nil(t, svc.actionEvent)

	// register an action event
	ch := make(chan dispatcher.DIDCommAction)
	err := svc.RegisterActionEvent(ch)
	require.NoError(t, err)

	// register another action event
	err = svc.RegisterActionEvent(make(chan dispatcher.DIDCommAction))
	require.Error(t, err)
	require.Contains(t, err.Error(), "channel is already registered for the action event")

	// validate after register
	require.NotNil(t, svc.actionEvent)

	// unregister a action event
	err = svc.UnregisterActionEvent(ch)
	require.NoError(t, err)

	// validate after unregister
	require.Nil(t, svc.actionEvent)

	// unregister with different channel
	err = svc.UnregisterActionEvent(make(chan dispatcher.DIDCommAction))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid channel passed to unregister the action event")
}

func TestService_MsgEvents(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()

	svc := New(dbstore, &mockProvider{})

	// validate before register
	require.Nil(t, svc.msgEvents)
	require.Equal(t, 0, len(svc.msgEvents))

	// register a status event
	ch := make(chan dispatcher.DIDCommMsg)
	err := svc.RegisterMsgEvent(ch)
	require.NoError(t, err)

	// validate after register
	require.NotNil(t, svc.msgEvents)
	require.Equal(t, 1, len(svc.msgEvents))

	// register a new status event
	err = svc.RegisterMsgEvent(make(chan dispatcher.DIDCommMsg))
	require.NoError(t, err)

	// validate after new register
	require.NotNil(t, svc.msgEvents)
	require.Equal(t, 2, len(svc.msgEvents))

	// unregister a status event
	err = svc.UnregisterMsgEvent(ch)
	require.NoError(t, err)

	// validate after unregister
	require.Equal(t, 1, len(svc.msgEvents))

	// add channels and remove in opposite order
	svc.msgEvents = nil
	ch1 := make(chan dispatcher.DIDCommMsg)
	ch2 := make(chan dispatcher.DIDCommMsg)
	ch3 := make(chan dispatcher.DIDCommMsg)

	err = svc.RegisterMsgEvent(ch1)
	require.NoError(t, err)

	err = svc.RegisterMsgEvent(ch2)
	require.NoError(t, err)

	err = svc.RegisterMsgEvent(ch3)
	require.NoError(t, err)

	err = svc.UnregisterMsgEvent(ch3)
	require.NoError(t, err)

	err = svc.UnregisterMsgEvent(ch2)
	require.NoError(t, err)

	err = svc.UnregisterMsgEvent(ch1)
	require.NoError(t, err)
}

func Test_AutoExecute(t *testing.T) {
	ch := make(chan dispatcher.DIDCommAction)
	done := make(chan struct{})

	go func() {
		require.NoError(t, AutoExecuteActionEvent(ch))
		close(done)
	}()

	close(ch)
	<-done
}

func TestServiceErrors(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()

	request, err := json.Marshal(
		&Request{
			Type:  ConnectionResponse,
			ID:    randomString(),
			Label: "test",
		},
	)
	require.NoError(t, err)

	msg := dispatcher.DIDCommMsg{
		Type:    ConnectionResponse,
		Payload: request,
	}

	svc := New(dbstore, &mockProvider{})
	actionCh := make(chan dispatcher.DIDCommAction, 10)
	err = svc.RegisterActionEvent(actionCh)
	require.NoError(t, err)

	// thid error
	err = svc.Handle(dispatcher.DIDCommMsg{Payload: nil})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot unmarshal @id and ~thread: error=")

	// state update error
	err = svc.update("", &responded{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to write to store")

	// fetch current state error
	svc.store = &mockStore{get: func(s string) (bytes []byte, e error) {
		return nil, errors.New("error")
	}}
	err = svc.Handle(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot fetch state from store")

	// invalid message type
	svc.store = dbstore
	msg.Type = "invalid"
	err = svc.Handle(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unrecognized msgType: invalid")

	// test handle - invalid state name
	msg.Type = ConnectionResponse
	message := &message{Msg: msg, ThreadID: randomString()}
	err = svc.handle(message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid state name:")

	// invalid state name
	message.NextStateName = stateNameInvited
	err = svc.handle(message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to execute state invited")

	// empty thread id
	message.NextStateName = stateNameNull
	message.ThreadID = ""
	err = svc.handle(message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to persist state null")
}
