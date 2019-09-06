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
	destinationURL  = "https://localhost:8090"
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

	require.NoError(t, prov.SendExchangeRequest(req, destinationURL))
	require.Error(t, prov.SendExchangeRequest(nil, destinationURL))
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

func TestService_Handle(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}

	// Invitation is sent by Alice
	payloadBytes, err := json.Marshal(
		&Invitation{
			Type:  "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation",
			ID:    "12345678900987654324",
			Label: "Alice",
			DID:   "did:sov:QmWbsNYhMrjHiqZDTUTEJs",
		})
	require.NoError(t, err)

	msg := dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation", Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	// Invitation accepted and Bob is sending exchange request to Alice
	payloadBytes, err = json.Marshal(
		&Request{
			Type:  "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
			ID:    "5369752154652",
			Label: "Bob",
			Connection: &Connection{
				DID: "B.did@B:A",
			},
		})
	require.NoError(t, err)

	msg = dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request", Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	// Alice is sending exchange-response to BOB
	payloadBytes, err = json.Marshal(
		&Response{
			Type:   "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
			ID:     "13354576764562",
			Thread: &decorator.Thread{ID: "5369752154652"},
			ConnectionSignature: &ConnectionSignature{
				Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
			},
		})
	require.NoError(t, err)

	msg = dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response", Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	// BOB is sending ack. TODO: This has to be done using RFCs 0015

	// Alice is sending exchange-response to BOB
	payloadBytes, err = json.Marshal(
		&Ack{
			Type:   "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
			ID:     "123564324344",
			Status: "OK",
			Thread: &decorator.Thread{ID: "5369752154652"},
		})
	require.NoError(t, err)
	msg = dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/ack", Payload: payloadBytes}
	err = s.Handle(msg)
	require.NoError(t, err)

	msg = dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/yzaldh", Payload: payloadBytes}
	err = s.Handle(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unrecognized msgType")
}

func TestService_Handle_StateTransitions(t *testing.T) {
	dbstore, cleanup := store(t)
	defer cleanup()
	m := mockProvider{}
	s := &Service{outboundTransport: m.OutboundTransport(), store: dbstore}

	t.Run("good state transition", func(t *testing.T) {
		thid := randomString()
		invitation, err := json.Marshal(
			&Invitation{
				Type:  "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation",
				ID:    thid,
				Label: "Alice",
				DID:   "did:sov:QmWbsNYhMrjHiqZDTUTEJs",
			})
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation", Payload: invitation})
		require.NoError(t, err)
		request, err := json.Marshal(
			&Request{
				Type:       "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
				ID:         randomString(),
				Label:      "test",
				Connection: &Connection{DID: "did:example:123"},
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request", Payload: request})
		require.NoError(t, err)
	})
	t.Run("good state transition without an invitation", func(t *testing.T) {
		request, err := json.Marshal(
			&Request{
				Type:       "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
				ID:         randomString(),
				Label:      "test",
				Connection: &Connection{DID: "did:example:123"},
			},
		)
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request", Payload: request})
		require.NoError(t, err)
	})

	t.Run("bad state transition", func(t *testing.T) {
		thid := randomString()
		invitation, err := json.Marshal(
			&Invitation{
				Type:  "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation",
				ID:    thid,
				Label: "Alice",
				DID:   "did:sov:QmWbsNYhMrjHiqZDTUTEJs",
			})
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation", Payload: invitation})
		require.NoError(t, err)

		response, err := json.Marshal(
			&Response{
				Type:   "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response",
				ID:     randomString(),
				Thread: &decorator.Thread{ID: thid},
				ConnectionSignature: &ConnectionSignature{
					Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
				},
			})
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response", Payload: response})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid state transition")
	})

	t.Run("illegal starting state", func(t *testing.T) {
		response, err := json.Marshal(
			&Response{
				Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response",
				ID:   randomString(),
				ConnectionSignature: &ConnectionSignature{
					Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
				},
			})
		require.NoError(t, err)
		err = s.Handle(dispatcher.DIDCommMsg{Type: "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response", Payload: response})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid state transition")
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
				get: func(string) ([]byte, error) { return nil, errors.New("not found") },
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
