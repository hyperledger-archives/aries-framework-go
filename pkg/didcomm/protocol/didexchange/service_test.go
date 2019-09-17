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

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/event"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	destinationURL  = "https://localhost:8090"
	successResponse = "success"
	invalidThreadID = "invalidThreadID"
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

func TestSendRequest(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	prov := New(dbstore, &mockProvider{})

	req := &Request{
		ID:    "5678876542345",
		Label: "Bob",
	}

	require.NoError(t, prov.SendExchangeRequest(req, destinationURL))
	require.Error(t, prov.SendExchangeRequest(nil, destinationURL))
}

func TestService_Name(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	prov := New(dbstore, &mockProvider{})

	require.Equal(t, DIDExchange, prov.Name())
}

func TestSendResponse(t *testing.T) {
	prov := New(nil, &mockProvider{})

	resp := &Response{
		ID: "12345678900987654321",
		ConnectionSignature: &ConnectionSignature{
			Type: "did:trustbloc:RQkehfoFssiwQRuihskwoPSR;spec/ed25519Sha512_single/1.0/ed25519Sha512_single",
		},
	}

	require.NoError(t, prov.SendExchangeResponse(resp, destinationURL))
	require.Error(t, prov.SendExchangeResponse(nil, destinationURL))
}

// did-exchange flow with role Inviter
func TestService_Handle_Inviter(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}
	s.RegisterAutoExecute()
	thid := randomString()

	// Invitation was previously sent by Alice to Bob.
	// Bob now sends a did-exchange Request
	payloadBytes, err := json.Marshal(
		&Request{
			Type:  ConnectionRequest,
			ID:    thid,
			Label: "Bob",
			Connection: &Connection{
				DID: "B.did@B:A",
			},
		})
	require.NoError(t, err)
	msg := dispatcher.DIDCommMsg{Type: ConnectionRequest, Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	// Alice automatically sends exchange Response to Bob
	// Bob replies with an ACK
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
	store := &mockStore{
		put: func(s string, bytes []byte) error {
			data[s] = string(bytes)
			return nil
		},
		get: func(s string) (bytes []byte, e error) {
			if state, found := data[s]; found {
				return []byte(state), nil
			}
			return nil, storage.ErrDataNotFound
		},
	}
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: store}
	s.RegisterAutoExecute()

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
	currentState, err := s.currentState(thid)
	require.NoError(t, err)
	require.Equal(t, (&completed{}).Name(), currentState.Name())
}

func TestService_Handle_EdgeCases(t *testing.T) {
	t.Run("must not start with Response msg", func(t *testing.T) {
		s := &Service{outboundTransport: newMockOutboundTransport(), store: newMockStore()}
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
		s := &Service{outboundTransport: newMockOutboundTransport(), store: newMockStore()}
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
		s := &Service{outboundTransport: newMockOutboundTransport(), store: newMockStore()}
		s.RegisterAutoExecute()
		thid := randomString()
		request, err := json.Marshal(
			&Request{
				Type:  ConnectionRequest,
				ID:    thid,
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: ConnectionRequest, Outbound: false, Payload: request})
		require.NoError(t, err)
		// state machine has automatically transitioned to responded state
		actual, err := s.currentState(thid)
		require.NoError(t, err)
		require.Equal(t, (&responded{}).Name(), actual.Name())
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
		s := &Service{
			outboundTransport: newMockOutboundTransport(),
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
		s := &Service{
			outboundTransport: newMockOutboundTransport(),
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
		s := &Service{outboundTransport: newMockOutboundTransport(), store: newMockStore()}
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
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}

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

func newMockOutboundTransport() transport.OutboundTransport {
	return (&mockProvider{}).OutboundTransport()
}

func newMockStore() storage.Store {
	data := make(map[string][]byte)
	return &mockStore{
		put: func(k string, v []byte) error {
			data[k] = v
			return nil
		},
		get: func(k string) ([]byte, error) {
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

func (p *mockProvider) OutboundTransport() transport.OutboundTransport {
	return didcomm.NewMockOutboundTransport(successResponse)
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

	svc := New(dbstore, &mockProvider{})
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

	validateStatusEventAction(t, svc)
}

func startConsumer(t *testing.T, svc *Service, done chan bool) {
	actionCh := make(chan event.DIDCommEvent, 10)
	err := svc.RegisterEvent(actionCh)
	require.NoError(t, err)

	go func() {
		for {
			select {
			// receive the events
			case e := <-actionCh:
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
		}
	}()

	statusCh := make(chan dispatcher.DIDCommMsg, 10)
	err = svc.RegisterMsg(statusCh)
	require.NoError(t, err)
	go func() {
		for {
			select {
			// receive the events
			case e := <-statusCh:
				switch e.Type {
				case ConnectionRequest:
					writeToDB(t, svc, e)
				}
			}
		}
	}()

}

func handleConnectionRequestEvents(t *testing.T, svc *Service, e event.DIDCommEvent, done chan bool) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionRequest, e.Message.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == "done" {
		done <- true
		return
	}
	err = func(e event.DIDCommEvent) error {
		err := json.Unmarshal(e.Message.Payload, &pl)
		require.NoError(t, err)

		if pl.ID == invalidThreadID {
			return errors.New("invalid id")
		}

		return nil
	}(e)

	// invoke callback
	e.Callback(event.DIDCommCallback{Err: err})

	if pl.ID == invalidThreadID {
		// no state change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "null", s.Name())
	} else {
		require.Fail(t, "handleConnectionRequestEvents tests are not validated")
	}
}

func handleConnectionResponseEvents(t *testing.T, svc *Service, e event.DIDCommEvent) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionResponse, e.Message.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == "change-id" {
		e.Callback = func(didCommCallback event.DIDCommCallback) {
			svc.processCallback("invalid-id", didCommCallback)
		}
	}

	if pl.ID == "handle-error" {
		jsonDoc, err := json.Marshal(&message{
			NextStateName: "invalid",
		})
		require.NoError(t, err)

		id := generateRandomID()
		err = svc.store.Put(id, jsonDoc)
		require.NoError(t, err)

		e.Callback = func(didCommCallback event.DIDCommCallback) {
			svc.processCallback(id, didCommCallback)
		}
	}

	// invoke callback
	e.Callback(event.DIDCommCallback{Err: nil})
	if pl.ID == "change-id" {
		// no state change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "requested", s.Name())
	} else if pl.ID == "handle-error" {
		// no s change since there was a error with processing
		s, err := svc.currentState(pl.ID)
		require.NoError(t, err)
		require.Equal(t, "requested", s.Name())
	} else {
		require.Fail(t, "handleConnectionResponseEvents tests are not validated")
	}
}

func handleConnectionAckEvents(t *testing.T, svc *Service, e event.DIDCommEvent) {
	require.NotEmpty(t, e.Message)
	require.Equal(t, ConnectionAck, e.Message.Type)

	pl := payload{}
	err := json.Unmarshal(e.Message.Payload, &pl)
	require.NoError(t, err)

	if pl.ID == "corrupt" {
		id := generateRandomID()
		err := svc.store.Put(id, []byte("invalid json"))
		require.NoError(t, err)

		e.Callback = func(didCommCallback event.DIDCommCallback) {
			svc.processCallback(id, didCommCallback)
		}
	}

	// invoke callback
	e.Callback(event.DIDCommCallback{Err: nil})
	if pl.ID == "corrupt" {
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
	svc.store.Put("status-event"+pl.ID, []byte("status_event"))
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
	id := "change-id"

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
	id := "corrupt"

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
	id := "handle-error"

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

func validateStatusEventAction(t *testing.T, svc *Service) {
	val, err := svc.store.Get("status-event" + invalidThreadID)
	require.NoError(t, err)
	require.Equal(t, "status_event", string(val))
}

func TestService_No_AutoExecution(t *testing.T) {

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

func TestService_Execute(t *testing.T) {

	dbstore, cleanup := store(t)
	defer cleanup()

	svc := New(dbstore, &mockProvider{})

	// validate before register
	require.Nil(t, svc.actionEvent)
	require.False(t, svc.execute)

	// register a action event
	ch := make(chan event.DIDCommEvent, 10)
	err := svc.RegisterEvent(ch)
	require.NoError(t, err)

	// validate after register
	require.NotNil(t, svc.actionEvent)
	require.True(t, svc.execute)

	// unregister a action event
	err = svc.UnregisterEvent()
	require.NoError(t, err)

	// validate after unregister
	require.Nil(t, svc.actionEvent)
	require.False(t, svc.execute)

	// register for auto execute
	err = svc.RegisterAutoExecute()
	require.NoError(t, err)
	require.True(t, svc.execute)

	// unregister for auto execute
	err = svc.UnregisterAutoExecute()
	require.NoError(t, err)
	require.False(t, svc.execute)

	// register for auto execute and action event
	err = svc.RegisterEvent(ch)
	require.NoError(t, err)
	err = svc.RegisterAutoExecute()
	require.NoError(t, err)
	require.True(t, svc.execute)

	// unregister action event with auto execute set
	err = svc.UnregisterEvent()
	require.NoError(t, err)
	require.False(t, svc.execute)
}

func TestService_StatusEvents(t *testing.T) {

	dbstore, cleanup := store(t)
	defer cleanup()

	svc := New(dbstore, &mockProvider{})

	// validate before register
	require.Nil(t, svc.statusEvents)
	require.Equal(t, 0, len(svc.statusEvents))

	// register a status event
	ch := make(chan dispatcher.DIDCommMsg, 10)
	err := svc.RegisterMsg(ch)
	require.NoError(t, err)

	// validate after register
	require.NotNil(t, svc.statusEvents)
	require.Equal(t, 1, len(svc.statusEvents))

	// register a new status event
	err = svc.RegisterMsg(make(chan dispatcher.DIDCommMsg, 10))
	require.NoError(t, err)

	// validate after new register
	require.NotNil(t, svc.statusEvents)
	require.Equal(t, 2, len(svc.statusEvents))

	// unregister a status event
	err = svc.UnregisterMsg(ch)
	require.NoError(t, err)

	// validate after unregister
	require.Equal(t, 1, len(svc.statusEvents))
}
