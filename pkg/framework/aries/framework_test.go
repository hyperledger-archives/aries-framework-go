// +build !js,!wasm

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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/didexchange"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/peer"
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
			WithPacker(func(ctx packer.Provider) (packer.Packer, error) {
				return &didcomm.MockAuthCrypt{
					EncryptValue: func(payload, senderPubKey []byte, recipients [][]byte) (bytes []byte, e error) {
						return []byte("packed message"), nil
					},
					DecryptValue: nil,
					Type:         "",
				}, nil
			},
				func(ctx packer.Provider) (packer.Packer, error) {
					return &didcomm.MockAuthCrypt{
						EncryptValue: nil,
						Type:         "dummy format",
					}, nil
				}))
		require.NoError(t, err)

		// context
		ctx, err := aries.Context()
		require.NoError(t, err)

		e := ctx.OutboundDispatcher().Send([]byte("Hello World"), "", &service.Destination{ServiceEndpoint: serverURL})
		require.NoError(t, e)
	})

	// framework new - success
	t.Run("test vdri - with user provided", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		vdri := &mockvdri.MockVDRI{}
		aries, err := New(WithVDRI(vdri), WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		require.Equal(t, len(aries.vdri), 1)
		require.Equal(t, vdri, aries.vdri[0])
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test error create vdri", func(t *testing.T) {
		_, err := New(
			WithStoreProvider(&storage.MockStoreProvider{FailNameSpace: peer.StoreNamespace}),
			WithInboundTransport(&mockInboundTransport{}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "create new vdri peer failed")
	})

	t.Run("test vdri - close error", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		vdri := &mockvdri.MockVDRI{CloseErr: fmt.Errorf("close vdri error")}
		aries, err := New(WithVDRI(vdri), WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		err = aries.Close()
		require.Error(t, err)
		require.Contains(t, err.Error(), "close vdri error")
	})

	t.Run("test vdri - with default vdri", func(t *testing.T) {
		// store peer DID in the store
		dbprov := leveldb.NewProvider(dbPath)
		peerDID := "did:peer:21tDAKCERh95uGgKbJNHYp"
		store, err := peer.New(dbprov)
		require.NoError(t, err)
		originalDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)
		err = store.Store(originalDoc, nil)
		require.NoError(t, err)

		err = dbprov.Close()
		require.NoError(t, err)

		// with default DID resolver
		aries, err := New(WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		resolvedDoc, err := aries.vdriRegistry.Resolve(peerDID)
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
			return &mockdidexchange.MockDIDExchangeSvc{
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
			return &mockdidexchange.MockDIDExchangeSvc{
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

	t.Run("test did connection store svc", func(t *testing.T) {
		fw := Aries{storeProvider: &storage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf("store err"),
		}}

		err := createDIDConnectionStore(&fw)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store err")
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

	t.Run("test new with outbound transport service", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		aries, err := New(WithOutboundTransports(&didcomm.MockOutboundTransport{ExpectedResponse: "data"},
			&didcomm.MockOutboundTransport{ExpectedResponse: "data1"}))
		require.NoError(t, err)
		require.Equal(t, 2, len(aries.outboundTransports))
		r, err := aries.outboundTransports[0].Send([]byte("data"), &service.Destination{ServiceEndpoint: "url"})
		require.NoError(t, err)
		require.Equal(t, "data", r)
		r, err = aries.outboundTransports[1].Send([]byte("data1"), &service.Destination{ServiceEndpoint: "url"})
		require.NoError(t, err)
		require.Equal(t, "data1", r)
		require.NoError(t, aries.Close())
	})

	t.Run("test new with transport return route", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		transportReturnRoute := decorator.TransportReturnRouteAll
		aries, err := New(WithTransportReturnRoute(transportReturnRoute))
		require.NoError(t, err)
		require.Equal(t, transportReturnRoute, aries.transportReturnRoute)
		require.NoError(t, aries.Close())

		transportReturnRoute = decorator.TransportReturnRouteThread
		_, err = New(WithTransportReturnRoute(transportReturnRoute))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid transport return route option : "+transportReturnRoute)

		transportReturnRoute = decorator.TransportReturnRouteNone
		aries, err = New(WithTransportReturnRoute(transportReturnRoute))
		require.NoError(t, err)
		require.Equal(t, transportReturnRoute, aries.transportReturnRoute)
		require.NoError(t, aries.Close())

		transportReturnRoute = "invalid-transport-route"
		_, err = New(WithTransportReturnRoute(transportReturnRoute))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid transport return route option : "+transportReturnRoute)
	})
}

func Test_Packager(t *testing.T) {
	t.Run("test error from packager svc - primary packer", func(t *testing.T) {
		f, err := New(WithInboundTransport(&mockInboundTransport{}),
			WithStoreProvider(storage.NewMockStoreProvider()),
			WithPacker(func(ctx packer.Provider) (packer.Packer, error) {
				return nil, fmt.Errorf("error from primary packer")
			}))
		require.Error(t, err)
		require.Nil(t, f)
		require.Contains(t, err.Error(), "error from primary packer")
	})

	t.Run("test error from packager svc - fallback packer", func(t *testing.T) {
		f, err := New(WithInboundTransport(&mockInboundTransport{}),
			WithStoreProvider(storage.NewMockStoreProvider()),
			WithPacker(func(ctx packer.Provider) (packer.Packer, error) {
				return nil, nil
			},
				func(ctx packer.Provider) (packer.Packer, error) {
					return nil, fmt.Errorf("error from fallback packer")
				}))
		require.Error(t, err)
		require.Nil(t, f)
		require.Contains(t, err.Error(), "error from fallback packer")
	})
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

func (m *mockInboundTransport) Start(prov transport.Provider) error {
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
