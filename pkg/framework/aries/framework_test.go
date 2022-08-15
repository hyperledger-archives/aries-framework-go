/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	didStoreMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/did"
	verifiableStoreMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/msghandler"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/generic"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	locallock "github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
)

//nolint:lll
const doc = `{
  "@context": ["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
  "verificationMethod": [
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
		// framework new - error
		_, err := New(func(opts *Aries) error {
			return errors.New("error creating the framework option")
		})
		require.Error(t, err)
	})

	t.Run("test framework new - with default outbound dispatcher", func(t *testing.T) {
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
			WithKMS(func(ctx kms.Provider) (kms.KeyManager, error) {
				return &mockkms.KeyManager{CreateKeyID: "abc"}, nil
			}),
			WithCrypto(&mockcrypto.Crypto{SignValue: []byte("mockValue")}),
			WithPacker(func(ctx packer.Provider) (packer.Packer, error) {
				return &didcomm.MockAuthCrypt{
					EncryptValue: func(cty string, payload, senderPubKey []byte, recipients [][]byte) (bytes []byte, e error) {
						return []byte("packed message"), nil
					},
					DecryptValue: nil,
				}, nil
			},
				func(ctx packer.Provider) (packer.Packer, error) {
					return &didcomm.MockAuthCrypt{
						EncryptValue: nil,
					}, nil
				}),
			WithMediaTypeProfiles([]string{"mockProfile"}))
		require.NoError(t, err)

		// context
		ctx, err := aries.Context()
		require.NoError(t, err)

		e := ctx.OutboundDispatcher().Send(
			[]byte("Hello World"),
			mockdiddoc.MockDIDKey(t),
			&service.Destination{ServiceEndpoint: model.NewDIDCommV1Endpoint(serverURL)},
		)
		require.NoError(t, e)
	})

	// framework new - success
	t.Run("test vdr - with DIDComm V2", func(t *testing.T) {
		vdr := &mockvdr.MockVDR{}
		aries, err := New(WithVDR(vdr), WithInboundTransport(&mockInboundTransport{}),
			WithMediaTypeProfiles([]string{transport.MediaTypeDIDCommV2Profile}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		require.Equal(t, len(aries.vdr), 1)
		require.Equal(t, vdr, aries.vdr[0])
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test vdr - with user provided", func(t *testing.T) {
		vdr := &mockvdr.MockVDR{}
		aries, err := New(WithVDR(vdr), WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		require.Equal(t, len(aries.vdr), 1)
		require.Equal(t, vdr, aries.vdr[0])
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test error create vdr", func(t *testing.T) {
		sp := storage.NewMockStoreProvider()
		sp.FailNamespace = peer.StoreNamespace

		_, err := New(
			WithStoreProvider(sp),
			WithInboundTransport(&mockInboundTransport{}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "create new vdr peer failed")
	})

	t.Run("test vdr - close error", func(t *testing.T) {
		vdr := &mockvdr.MockVDR{CloseErr: fmt.Errorf("close vdr error")}
		aries, err := New(WithVDR(vdr), WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		err = aries.Close()
		require.Error(t, err)
		require.Contains(t, err.Error(), "close vdr error")
	})

	t.Run("test vdr - with default vdr", func(t *testing.T) {
		t.Skip()
		// store peer DID in the store
		dbprov := mem.NewProvider()
		peerDID := "did:peer:21tDAKCERh95uGgKbJNHYp"
		store, err := peer.New(dbprov)
		require.NoError(t, err)
		originalDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)
		_, err = store.Create(originalDoc)
		require.NoError(t, err)

		err = dbprov.Close()
		require.NoError(t, err)

		// with default DID resolver
		aries, err := New(WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		resolvedDoc, err := aries.vdrRegistry.Resolve(peerDID)
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
		newMockSvc := api.ProtocolSvcCreator{
			Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
				return &mockdidexchange.MockDIDExchangeSvc{
					ProtocolName: "mockProtocolSvc",
				}, nil
			},
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
		mockSvcCreator := api.ProtocolSvcCreator{
			Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
				return &mockdidexchange.MockDIDExchangeSvc{
					ProtocolName: "mockProtocolSvc",
				}, nil
			},
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
		newMockSvc := api.ProtocolSvcCreator{
			Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
				return nil, errors.New("error creating the protocol")
			},
		}
		_, err := New(WithProtocols(newMockSvc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the protocol")

		newMockSvc = api.ProtocolSvcCreator{
			Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
				return &mockdidexchange.MockDIDExchangeSvc{
					ProtocolName: "mockProtocolSvc",
				}, nil
			},

			Init: func(srv dispatcher.ProtocolService, prv api.Provider) error {
				return errors.New("error initializing the protocol")
			},
		}

		_, err = New(WithProtocols(newMockSvc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error initializing the protocol")

		newMockSvc = api.ProtocolSvcCreator{
			Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
				return &mockProtocolService{}, nil
			},
		}

		_, err = New(WithProtocols(newMockSvc))
		require.Error(t, err)
		require.ErrorIs(t, err, errMockProtocolInit)
	})

	t.Run("test Inbound transport - with options", func(t *testing.T) {
		aries, err := New(WithInboundTransport(&mockInboundTransport{}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)
	})

	t.Run("test Inbound transport - start/stop error", func(t *testing.T) {
		// start error
		_, err := New(WithInboundTransport(&mockInboundTransport{startError: errors.New("start error")}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound transport start failed")

		// stop error
		aries, err := New(WithInboundTransport(&mockInboundTransport{stopError: errors.New("stop error")}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		err = aries.Close()
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound transport close failed")
	})

	t.Run("test KMS svc - with user provided instance", func(t *testing.T) {
		// with custom KMS
		aries, err := New(WithInboundTransport(&mockInboundTransport{}),
			WithKMS(func(ctx kms.Provider) (kms.KeyManager, error) {
				return &mockkms.KeyManager{CreateKeyID: "abc"}, nil
			}),
			WithCrypto(&mockcrypto.Crypto{SignValue: []byte("mockValue")}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		v, err := ctx.Crypto().Sign(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test crypto svc - with user provided crypto - Encrypt success", func(t *testing.T) {
		// with custom crypto
		aries, err := New(WithCrypto(&mockcrypto.Crypto{
			EncryptValue:      []byte("mockValue"),
			EncryptNonceValue: []byte("mockNonce"),
		}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		v, n, err := ctx.Crypto().Encrypt([]byte{}, []byte{}, nil)
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		require.Equal(t, []byte("mockNonce"), n)
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test crypto svc - with user provided crypto - Encrypt fail", func(t *testing.T) {
		// with custom crypto
		aries, err := New(WithCrypto(&mockcrypto.Crypto{
			EncryptErr: fmt.Errorf("error encrypting from crypto"),
		}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		_, _, err = ctx.Crypto().Encrypt([]byte{}, []byte{}, nil)
		require.EqualError(t, err, "error encrypting from crypto")
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test crypto svc - with user provided crypto - Sign success", func(t *testing.T) {
		// with custom crypto
		aries, err := New(WithCrypto(&mockcrypto.Crypto{SignValue: []byte("mockValue")}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		v, err := ctx.Crypto().Sign(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test crypto svc - with user provided crypto - Sign fail", func(t *testing.T) {
		// with custom crypto
		aries, err := New(WithCrypto(&mockcrypto.Crypto{
			SignErr: fmt.Errorf("error signing from crypto"),
		}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		_, err = ctx.Crypto().Sign(nil, "")
		require.EqualError(t, err, "error signing from crypto")
		err = aries.Close()
		require.NoError(t, err)
	})

	t.Run("test error from kms svc", func(t *testing.T) {
		// with custom legacy kms
		_, err := New(WithInboundTransport(&mockInboundTransport{}),
			WithKMS(func(ctx kms.Provider) (kms.KeyManager, error) {
				return nil, fmt.Errorf("error from KMS")
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error from KMS")
	})

	t.Run("test new with explicitly passing noop secret lock svc as an option", func(t *testing.T) {
		// create noop secret lock service
		s := &noop.NoLock{}

		// final step, create the Aries agent with this secret lock
		a, err := New(WithSecretLock(s), WithStoreProvider(storage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, a)
		require.Equal(t, s, a.secretLock)

		err = a.Close()
		require.NoError(t, err)
	})

	t.Run("test new with custom (unprotected master key) secret lock svc and with custom KMS", func(t *testing.T) {
		masterKeyFilePath := "masterKey_aries.txt"
		tmpfile, err := ioutil.TempFile("", masterKeyFilePath)
		require.NoError(t, err)

		defer func() {
			// close file
			require.NoError(t, tmpfile.Close())
			// clean up
			require.NoError(t, os.Remove(tmpfile.Name()))
		}()

		keySize := sha256.Size

		// generate a random master key
		masterKeyContent := make([]byte, keySize)
		_, err = rand.Read(masterKeyContent)
		require.NoError(t, err)
		require.NotEmpty(t, masterKeyContent)

		// store masterKeyContent to file
		n, err := tmpfile.Write([]byte(base64.URLEncoding.EncodeToString(masterKeyContent)))
		require.NoError(t, err)
		require.Equal(t, base64.URLEncoding.EncodedLen(keySize), n)

		r, err := locallock.MasterKeyFromPath(tmpfile.Name())
		require.NoError(t, err)
		require.NotEmpty(t, r)

		s, err := locallock.NewService(r, nil)
		require.NoError(t, err)
		require.NotEmpty(t, s)

		// final step, create the Aries agent with this secret lock
		a, err := New(WithSecretLock(s), WithStoreProvider(storage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, a)
		require.Equal(t, s, a.secretLock)

		err = a.Close()
		require.NoError(t, err)
	})

	t.Run("test new with custom (protected) secret lock svc and with custom KMS", func(t *testing.T) {
		// pre steps (preparation), create a protected master key and store it in a local file
		masterKeyFilePath := "masterKey_aries.txt"
		tmpfile, err := ioutil.TempFile("", masterKeyFilePath)
		require.NoError(t, err)

		defer func() {
			// close file
			require.NoError(t, tmpfile.Close())
			// clean up
			require.NoError(t, os.Remove(tmpfile.Name()))
		}()

		passphrase := "testPassword"
		keySize := sha256.Size

		salt := make([]byte, keySize)
		_, err = rand.Read(salt)
		require.NoError(t, err)

		// create a master lock to protect the master key (salt is optional)
		masterLock, err := hkdf.NewMasterLock(passphrase, sha256.New, salt)
		require.NoError(t, err)
		require.NotEmpty(t, masterLock)

		// generate a random master key
		masterKeyContent := make([]byte, keySize)
		_, err = rand.Read(masterKeyContent)
		require.NoError(t, err)
		require.NotEmpty(t, masterKeyContent)

		// encrypt it
		masterKeyEnc, err := masterLock.Encrypt("", &secretlock.EncryptRequest{
			Plaintext: string(masterKeyContent),
		})
		require.NoError(t, err)
		require.NotEmpty(t, masterKeyEnc)

		// store encrypted content to file
		n, err := tmpfile.Write([]byte(masterKeyEnc.Ciphertext))
		require.NoError(t, err)
		require.Equal(t, len(masterKeyEnc.Ciphertext), n)

		r, err := locallock.MasterKeyFromPath(tmpfile.Name())
		require.NoError(t, err)
		require.NotEmpty(t, r)

		s, err := locallock.NewService(r, masterLock)
		require.NoError(t, err)
		require.NotEmpty(t, s)

		// final step, create the Aries agent with this secret lock
		a, err := New(WithSecretLock(s), WithStoreProvider(storage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, a)
		require.Equal(t, s, a.secretLock)

		err = a.Close()
		require.NoError(t, err)

		// now test New with a custom kms using the same secretlock created above
		// create the kms provider first..
		p, err := context.New(
			context.WithSecretLock(s),
			context.WithStorageProvider(storage.NewMockStoreProvider()),
		)
		require.NoError(t, err)

		kmsStore, err := kms.NewAriesProviderWrapper(p.StorageProvider())
		require.NoError(t, err)

		kmsProv := &kmsProvider{
			kmsStore:          kmsStore,
			secretLockService: p.SecretLock(),
		}

		// create a custom KMS instance with this provider
		customKMS, err := localkms.New("local-lock://custom/master/key/", kmsProv)
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		// finally test New using a KMSCreator function returning the above customKMS
		a, err = New(WithKMS(func(ctx kms.Provider) (kms.KeyManager, error) {
			return customKMS, nil
		}), WithStoreProvider(storage.NewMockStoreProvider()))
		require.NoError(t, err)
		require.NotEmpty(t, a)
		require.Equal(t, customKMS, a.kms)

		err = a.Close()
		require.NoError(t, err)
	})

	t.Run("test protocol state store - with user provided protocol state store", func(t *testing.T) {
		s := storage.NewMockStoreProvider()

		aries, err := New(WithInboundTransport(&mockInboundTransport{}), WithProtocolStateStoreProvider(s))
		require.NoError(t, err)
		require.NotEmpty(t, aries)
		require.Equal(t, s, aries.protocolStateStoreProvider)
	})

	t.Run("test new with outbound transport service", func(t *testing.T) {
		aries, err := New(WithOutboundTransports(&didcomm.MockOutboundTransport{ExpectedResponse: "data"},
			&didcomm.MockOutboundTransport{ExpectedResponse: "data1"}))
		require.NoError(t, err)
		require.Equal(t, 2, len(aries.outboundTransports))
		r, err := aries.outboundTransports[0].Send([]byte("data"),
			&service.Destination{ServiceEndpoint: model.NewDIDCommV1Endpoint("url")})
		require.NoError(t, err)
		require.Equal(t, "data", r)
		r, err = aries.outboundTransports[1].Send([]byte("data1"),
			&service.Destination{ServiceEndpoint: model.NewDIDCommV1Endpoint("url")})
		require.NoError(t, err)
		require.Equal(t, "data1", r)
		require.NoError(t, aries.Close())
	})

	t.Run("test new with messenger handler", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		messengerHandler := mocks.NewMockMessengerHandler(ctrl)
		aries, err := New(WithMessengerHandler(messengerHandler))
		require.NoError(t, err)
		require.Equal(t, messengerHandler, aries.Messenger())
	})

	t.Run("test new with transport return route", func(t *testing.T) {
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

	t.Run("test message service provider option", func(t *testing.T) {
		// custom message service provider
		handler := msghandler.NewMockMsgServiceProvider()
		aries, err := New(WithMessageServiceProvider(handler))
		require.NoError(t, err)

		err = handler.Register(&generic.MockMessageSvc{})
		require.NoError(t, err)

		require.NotNil(t, aries)
		require.NotNil(t, aries.msgSvcProvider)
	})

	t.Run("test default message service provider option", func(t *testing.T) {
		// default message service provider
		aries, err := New()
		require.NoError(t, err)
		require.NotNil(t, aries.msgSvcProvider)
		require.Empty(t, aries.msgSvcProvider.Services())
	})

	t.Run("test verifiable store option", func(t *testing.T) {
		mockStore := &verifiableStoreMocks.MockStore{}
		// default message service provider
		aries, err := New(WithVerifiableStore(mockStore))
		require.NoError(t, err)
		require.Equal(t, mockStore, aries.verifiableStore)
	})

	t.Run("test DID connection store option", func(t *testing.T) {
		mockStore := &didStoreMocks.MockConnectionStore{}
		aries, err := New(WithDIDConnectionStore(mockStore))
		require.NoError(t, err)
		require.Equal(t, mockStore, aries.didConnectionStore)
	})

	t.Run("test JSON-LD context store option", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()

		aries, err := New(WithJSONLDContextStore(store))
		require.NoError(t, err)
		require.Equal(t, store, aries.contextStore)
	})

	t.Run("test JSON-LD remote provider store option", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()

		aries, err := New(WithJSONLDRemoteProviderStore(store))
		require.NoError(t, err)
		require.Equal(t, store, aries.remoteProviderStore)
	})

	t.Run("test JSON-LD document loader option", func(t *testing.T) {
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		aries, err := New(WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.Equal(t, loader, aries.documentLoader)
	})

	t.Run("test KeyType and KeyAgreement option", func(t *testing.T) {
		aries, err := New(WithKeyType(kms.BLS12381G2Type), WithKeyAgreementType(kms.NISTP384ECDHKWType))
		require.NoError(t, err)
		require.Equal(t, kms.BLS12381G2Type, aries.keyType)
		require.Equal(t, kms.NISTP384ECDHKWType, aries.keyAgreementType)
	})

	t.Run("test new with mediaTypeProfiles", func(t *testing.T) {
		aries, err := New(WithMediaTypeProfiles([]string{
			transport.MediaTypeV2EncryptedEnvelope,
			transport.MediaTypeV1EncryptedEnvelope,
		}))
		require.NoError(t, err)
		require.Equal(t, 2, len(aries.mediaTypeProfiles))
		require.Equal(t, transport.MediaTypeV2EncryptedEnvelope, aries.mediaTypeProfiles[0])
		require.Equal(t, transport.MediaTypeV1EncryptedEnvelope, aries.mediaTypeProfiles[1])
	})

	t.Run("failure while creating KMS Aries provider wrapper", func(t *testing.T) {
		mockStoreProvider := &storage.MockStoreProvider{
			FailNamespace: kms.AriesWrapperStoreName,
			Store: &storage.MockStore{
				Store: map[string]storage.DBEntry{},
			},
		}

		aries, err := New(WithStoreProvider(mockStoreProvider))
		require.EqualError(t, err, "create Aries provider KMS store wrapper failed: "+
			"failed to open store for name space kmsdb")
		require.Nil(t, aries)
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

type mockHTTPHandler struct{}

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

type mockProtocolService struct{}

func (m mockProtocolService) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	panic("implement me")
}

func (m mockProtocolService) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	panic("implement me")
}

func (m mockProtocolService) Accept(msgType string) bool {
	panic("implement me")
}

func (m mockProtocolService) Name() string {
	panic("implement me")
}

var errMockProtocolInit = errors.New("mock protocol init error")

func (m mockProtocolService) Initialize(i interface{}) error {
	return errMockProtocolInit
}
