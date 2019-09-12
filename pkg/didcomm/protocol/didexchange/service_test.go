/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
)

const (
	successResponse = "success"
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
	//this should get populated from an invitation payload
	dest := &Destination{
		RecipientKeys:[]string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://localhost:8090",
		RoutingKeys:[]string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	}
	require.NoError(t, prov.SendExchangeRequest(req, dest))
	require.Error(t, prov.SendExchangeRequest(nil, dest))
}

func TestSendResponse(t *testing.T) {
	prov := New(nil, &mockProvider{})

	resp := &Response{
		ID: "12345678900987654321",
		ConnectionSignature: &ConnectionSignature{
			Type: "did:trustbloc:RQkehfoFssiwQRuihskwoPSR;spec/ed25519Sha512_single/1.0/ed25519Sha512_single",
		},
	}
	dest := &Destination{
		RecipientKeys:[]string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://localhost:8090",
		RoutingKeys:[]string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	}
	require.NoError(t, prov.SendExchangeResponse(resp, dest))
	require.Error(t, prov.SendExchangeResponse(nil, dest))
}

// did-exchange flow with role Inviter
func TestService_Handle_Inviter(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}
	thid := randomString()

	// Invitation was previously sent by Alice to Bob.
	// Bob now sends a did-exchange Request
	payloadBytes, err := json.Marshal(
		&Request{
			Type:  connectionRequest,
			ID:    thid,
			Label: "Bob",
			Connection: &Connection{
				DID: "B.did@B:A",
			},
		})
	require.NoError(t, err)
	msg := dispatcher.DIDCommMsg{Type: connectionRequest, Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	// Alice automatically sends exchange Response to Bob
	// Bob replies with an ACK
	payloadBytes, err = json.Marshal(
		&Ack{
			Type:   connectionAck,
			ID:     randomString(),
			Status: "OK",
			Thread: &decorator.Thread{ID: thid},
		})
	require.NoError(t, err)
	msg = dispatcher.DIDCommMsg{Type: connectionAck, Payload: payloadBytes}
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

	// Alice receives an invitation from Bob
	payloadBytes, err := json.Marshal(
		&Invitation{
			Type:  connectionInvite,
			ID:    randomString(),
			Label: "Bob",
			DID:   "did:example:bob",
		},
	)
	require.NoError(t, err)
	msg := dispatcher.DIDCommMsg{Type: connectionInvite, Outbound: false, Payload: payloadBytes}
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
			Type:   connectionResponse,
			ID:     randomString(),
			Thread: &decorator.Thread{ID: thid},
		},
	)
	require.NoError(t, err)
	msg = dispatcher.DIDCommMsg{Type: connectionResponse, Outbound: false, Payload: payloadBytes}
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
				Type: connectionResponse,
				ID:   randomString(),
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: connectionResponse, Payload: response})
		require.Error(t, err)
	})
	t.Run("must not start with ACK msg", func(t *testing.T) {
		s := &Service{outboundTransport: newMockOutboundTransport(), store: newMockStore()}
		ack, err := json.Marshal(
			&Ack{
				Type: connectionAck,
				ID:   randomString(),
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: connectionAck, Payload: ack})
		require.Error(t, err)
	})
	t.Run("must not transition to same state", func(t *testing.T) {
		s := &Service{outboundTransport: newMockOutboundTransport(), store: newMockStore()}
		thid := randomString()
		request, err := json.Marshal(
			&Request{
				Type:  connectionRequest,
				ID:    thid,
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: connectionRequest, Outbound: false, Payload: request})
		require.NoError(t, err)
		// state machine has automatically transitioned to responded state
		actual, err := s.currentState(thid)
		require.NoError(t, err)
		require.Equal(t, (&responded{}).Name(), actual.Name())
		// therefore cannot transition Responded state
		response, err := json.Marshal(
			&Response{
				Type:   connectionResponse,
				ID:     randomString(),
				Thread: &decorator.Thread{ID: thid},
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: connectionResponse, Outbound: false, Payload: response})
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
				Type:  connectionRequest,
				ID:    randomString(),
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: connectionRequest, Outbound: false, Payload: request})
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
				Type:  connectionRequest,
				ID:    randomString(),
				Label: "test",
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: connectionRequest, Outbound: false, Payload: request})
		require.Error(t, err)
	})

	t.Run("error on invalid msg type", func(t *testing.T) {
		s := &Service{outboundTransport: newMockOutboundTransport(), store: newMockStore()}
		request, err := json.Marshal(
			&Request{
				Type:  connectionRequest,
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

//TODO: Use in memory store rather than level DB " https://github.com/hyperledger/aries-framework-go/issues/202
func store(t testing.TB) (store storage.Store, cleanup func()) {
	path, cleanup := tempDir(t)
	prov, err := leveldb.NewProvider(path)
	require.NoError(t, err)
	dbstore, err := prov.GetStoreHandle()
	require.NoError(t, err)
	return dbstore, cleanup
}

func tempDir(t testing.TB) (string, func()) {
	dbPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}
	return dbPath, func() {
		err := os.RemoveAll(dbPath)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}

func randomString() string {
	u := uuid.New()
	return u.String()
}
