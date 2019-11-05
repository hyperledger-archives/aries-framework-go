/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didmethod/peer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	mockenvelope "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockdidstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didstore"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
)

//nolint:lll
const doc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:peer:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:peer:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:peer:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:peer:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ]
}`

func TestFramework(t *testing.T) {
	t.Run("test framework new - returns error", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		// framework new - error
		_, err := New(func(opts *Aries) error {
			return errors.New("error creating the framework option")
		})
		require.Error(t, err)
	})

	t.Run("test framework new - with default outbound dispatcher", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		// prepare http server
		server := startMockServer(t, mockHTTPHandler{})
		port := getServerPort(server)
		defer func() {
			err := server.Close()
			if err != nil {
				t.Fatalf("Failed to stop server: %s", err)
			}
		}()
		serverURL := fmt.Sprintf("http://localhost:%d", port)

		aries, err := New(
			WithInboundTransport(&mockInboundTransport{}),
			WithKMS(func(ctx api.Provider) (api.CloseableKMS, error) {
				return &mockkms.CloseableKMS{SignMessageValue: []byte("mockValue")}, nil
			}),
			WithCrypter(func(ctx crypto.Provider) (crypto.Crypter, error) {
				return &didcomm.MockAuthCrypt{EncryptValue: nil}, nil
			}),
			WithPackager(func(ctx envelope.Provider) (envelope.Packager, error) {
				return &mockenvelope.BasePackager{PackValue: []byte("mockPackValue")}, nil
			}))
		require.NoError(t, err)

		// context
		ctx, err := aries.Context()
		require.NoError(t, err)

		e := ctx.OutboundDispatcher().Send([]byte("Hello World"), "", &service.Destination{ServiceEndpoint: serverURL})
		require.NoError(t, e)
	})

	t.Run("test framework new - with inject outbound dispatcher", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		aries, err := New(WithInboundTransport(&mockInboundTransport{}),
			WithOutboundDispatcher(func(prv dispatcher.Provider) (outbound dispatcher.Outbound, e error) {
				return &mockdispatcher.MockOutbound{}, nil
			}))
		require.NoError(t, err)

		// context
		ctx, err := aries.Context()
		require.NoError(t, err)

		e := ctx.OutboundDispatcher().Send([]byte("Hello World"), "", &service.Destination{})
		require.NoError(t, e)
	})

	t.Run("test framework new - error from create outbound dispatcher", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		_, err := New(WithInboundTransport(&mockInboundTransport{}),
			WithOutboundDispatcher(func(prv dispatcher.Provider) (outbound dispatcher.Outbound, e error) {
				return nil, fmt.Errorf("create outbound dispatcher error")
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "create outbound dispatcher error")
	})

	// framework new - success
	t.Run("test DID resolver - with user provided resolver", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		peerDID := "did:peer:123"
		// with consumer provider DID resolver
		resolver := didresolver.New(
			didresolver.WithDidMethod(mockDidMethod{readValue: []byte(doc), acceptFunc: func(method string) bool {
				return method == "peer"
			}}))
		aries, err := New(WithDIDResolver(resolver), WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		resolvedDoc, err := aries.DIDResolver().Resolve(peerDID)
		require.NoError(t, err)
		originalDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		require.Equal(t, originalDoc, resolvedDoc)
		err = aries.Close()
		require.NoError(t, err)
	})

	// framework new - success
	t.Run("test DID resolver - with default resolver", func(t *testing.T) {
		// store peer DID in the store
		dbprov, err := leveldb.NewProvider(dbPath)
		require.NoError(t, err)

		peerDID := "did:peer:21tDAKCERh95uGgKbJNHYp"
		store, err := peer.NewDIDStore(dbprov)
		require.NoError(t, err)
		originalDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)
		err = store.Put(originalDoc, nil)
		require.NoError(t, err)

		err = dbprov.Close()
		require.NoError(t, err)

		// with default DID resolver
		aries, err := New(WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		resolvedDoc, err := aries.DIDResolver().Resolve(peerDID)
		require.NoError(t, err)
		require.Equal(t, originalDoc, resolvedDoc)
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test protocol svc - with default protocol", func(t *testing.T) {
		aries, err := New(WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		_, err = ctx.Service(didexchange.DIDExchange)
		require.NoError(t, err)
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test protocol svc - with user provided protocol", func(t *testing.T) {
		newMockSvc := func(prv api.Provider) (dispatcher.Service, error) {
			return &protocol.MockDIDExchangeSvc{
				ProtocolName: "mockProtocolSvc",
			}, nil
		}
		// with custom protocol
		aries, err := New(WithProtocols(newMockSvc), WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		_, err = ctx.Service(didexchange.DIDExchange)
		require.NoError(t, err)

		_, err = ctx.Service("mockProtocolSvc")
		require.NoError(t, err)

		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test new with protocol service", func(t *testing.T) {
		mockSvcCreator := func(prv api.Provider) (dispatcher.Service, error) {
			return &protocol.MockDIDExchangeSvc{
				ProtocolName: "mockProtocolSvc",
			}, nil
		}
		aries, err := New(WithProtocols(mockSvcCreator), WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)

		prov, err := aries.Context()
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc")
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc1")
		require.Error(t, err)
	})

	t.Run("test error from protocol service", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		newMockSvc := func(prv api.Provider) (dispatcher.Service, error) {
			return nil, errors.New("error creating the protocol")
		}
		_, err := New(WithProtocols(newMockSvc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the protocol")
	})

	t.Run("test Inbound transport - with options", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		aries, err := New(WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)
	})

	t.Run("test Inbound transport - default", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		currentInboundPort := defaultInboundPort
		defaultInboundPort = ":26501"
		defer func() {
			defaultInboundPort = currentInboundPort
		}()

		aries, err := New()
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test Inbound transport - start/stop error", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		// start error
		_, err := New(WithInboundTransport(&mockInboundTransport{startError: errors.New("start error")}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound transport start failed")

		path, cleanup = generateTempDir(t)
		defer cleanup()
		dbPath = path

		// stop error
		aries, err := New(WithInboundTransport(&mockInboundTransport{stopError: errors.New("stop error")}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		err = aries.Close()
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound transport close failed")
	})

	t.Run("test kms svc - with user provided kms", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		// with custom kms
		aries, err := New(WithInboundTransport(&mockInboundTransport{}),
			WithKMS(func(ctx api.Provider) (api.CloseableKMS, error) {
				return &mockkms.CloseableKMS{SignMessageValue: []byte("mockValue")}, nil
			}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		v, err := ctx.Signer().SignMessage(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test error from kms svc", func(t *testing.T) {
		// with custom kms
		_, err := New(WithInboundTransport(&mockInboundTransport{}),
			WithKMS(func(ctx api.Provider) (api.CloseableKMS, error) {
				return nil, fmt.Errorf("error from kms")
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error from kms")
	})

	t.Run("test DID store - with default", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		originalDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		// with default DID store
		aries, err := New(WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		err = aries.didStore.Put(originalDoc)
		require.NoError(t, err)
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test DID store - with user provided did store", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		originalDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		// with default DID store
		aries, err := New(WithInboundTransport(&mockInboundTransport{}), WithDIDStore(mockdidstore.NewMockDidStore()))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		err = aries.didStore.Put(originalDoc)
		require.NoError(t, err)
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test transient store - with user provided transient store", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path
		s := storage.NewMockStoreProvider()

		aries, err := New(WithInboundTransport(&mockInboundTransport{}), WithTransientStoreProvider(s))
		require.NoError(t, err)
		require.NotEmpty(t, aries)
		require.Equal(t, s, aries.transientStoreProvider)
	})
}

type mockDidMethod struct {
	readValue  []byte
	readErr    error
	acceptFunc func(method string) bool
}

func (m mockDidMethod) Read(id string, opts ...didresolver.ResolveOpt) ([]byte, error) {
	return m.readValue, m.readErr
}

func (m mockDidMethod) Accept(method string) bool {
	return m.acceptFunc(method)
}

func generateTempDir(t testing.TB) (string, func()) {
	path, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}
	return path, func() {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}

func startMockServer(t *testing.T, handler http.Handler) net.Listener {
	// ":0" will make the listener auto assign a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		err := http.Serve(listener, handler)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			require.NoError(t, err)
		}
	}()
	return listener
}

type mockHTTPHandler struct {
}

func (m mockHTTPHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.Body != nil {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil || string(body) == "bad" {
			res.WriteHeader(http.StatusBadRequest)
			res.Write([]byte(fmt.Sprintf("bad request: %s", body))) // nolint
			return
		}
	}

	// mocking successful response
	res.WriteHeader(http.StatusAccepted)
	res.Write([]byte("success")) // nolint
}

func getServerPort(server net.Listener) int {
	return server.Addr().(*net.TCPAddr).Port
}

type mockInboundTransport struct {
	startError error
	stopError  error
}

func (m *mockInboundTransport) Start(prov transport.InboundProvider) error {
	if m.startError != nil {
		return m.startError
	}
	return nil
}

func (m *mockInboundTransport) Stop() error {
	if m.stopError != nil {
		return m.stopError
	}
	return nil
}

func (m *mockInboundTransport) Endpoint() string {
	return ""
}
