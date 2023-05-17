/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/did/endpoint"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

func TestDIDCreator(t *testing.T) {
	sProvider := storage.NewMockStoreProvider()
	km := newKMS(t, sProvider)

	t.Run("test create without service type", func(t *testing.T) {
		c, err := New(sProvider)
		require.NoError(t, err)
		require.NotNil(t, c)

		docResolution, err := c.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{getSigningKey()}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		// verify empty services
		require.Empty(t, docResolution.DIDDocument.Service)
	})

	t.Run("test create using didDoc without VerificationMethod", func(t *testing.T) {
		c, err := New(sProvider)
		require.NoError(t, err)
		require.NotNil(t, c)

		_, err = c.Create(&did.Doc{})
		require.EqualError(t, err, "create peer DID : verification method and key agreement are empty, at "+
			"least one should be set")
	})

	t.Run("test create using didDoc with VerificationMethod having undefined Type", func(t *testing.T) {
		c, err := New(sProvider)
		require.NoError(t, err)
		require.NotNil(t, c)

		vm := getSigningKey()
		vm.Type = "undefined"

		_, err = c.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{vm}})
		require.EqualError(t, err, "create peer DID : not supported VerificationMethod public key type: undefined")
	})

	t.Run("test request overrides", func(t *testing.T) {
		c, err := New(sProvider)
		require.NoError(t, err)
		require.NotNil(t, c)

		routingKeys := []string{"abc", "xyz"}
		docResolution, err := c.Create(
			&did.Doc{VerificationMethod: []did.VerificationMethod{getSigningKey()}, Service: []did.Service{{
				ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("request-endpoint"),
				RoutingKeys:     routingKeys,
				Type:            "request-type",
			}}})

		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		// verify service not empty, type and endpoint from request options
		require.NotEmpty(t, docResolution.DIDDocument.Service)
		require.Equal(t, "request-type", docResolution.DIDDocument.Service[0].Type)
		uri, err := docResolution.DIDDocument.Service[0].ServiceEndpoint.URI()
		require.NoError(t, err)
		require.Equal(t, "request-endpoint", uri)
		require.Equal(t, routingKeys, docResolution.DIDDocument.Service[0].RoutingKeys)
	})

	t.Run("test request overrides with keyAgreement", func(t *testing.T) {
		c, err := New(sProvider)
		require.NoError(t, err)
		require.NotNil(t, c)

		sVM, eVM := getSigningAndKeyAgreementKey(t, false, km)

		routingKeys := []string{"abc", "xyz"}
		docResolution, err := c.Create(
			&did.Doc{
				VerificationMethod: []did.VerificationMethod{sVM}, Service: []did.Service{{
					ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("request-endpoint"),
					RoutingKeys:     routingKeys,
					Type:            "request-type",
				}},
				KeyAgreement: []did.Verification{eVM},
			})

		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		// verify service not empty, type and endpoint from request options
		require.NotEmpty(t, docResolution.DIDDocument.Service)
		require.Equal(t, "request-type", docResolution.DIDDocument.Service[0].Type)
		uri, err := docResolution.DIDDocument.Service[0].ServiceEndpoint.URI()
		require.NoError(t, err)
		require.Equal(t, "request-endpoint", uri)

		// verify KeyAgreement
		require.Len(t, docResolution.DIDDocument.KeyAgreement, 1)
		require.EqualValues(t, eVM, docResolution.DIDDocument.KeyAgreement[0])
	})

	t.Run("test accept", func(t *testing.T) {
		c, err := New(sProvider)
		require.NoError(t, err)
		require.NotNil(t, c)

		accepted := c.Accept("invalid")
		require.False(t, accepted)

		accepted = c.Accept("peer")
		require.True(t, accepted)
	})
}

func TestBuild(t *testing.T) {
	sProvider := storage.NewMockStoreProvider()
	km := newKMS(t, sProvider)
	t.Run("inlined recipient keys for didcomm", func(t *testing.T) {
		expected := getSigningKey()
		c, err := New(sProvider)
		require.NoError(t, err)

		result, err := c.Create(
			&did.Doc{VerificationMethod: []did.VerificationMethod{expected}, Service: []did.Service{{
				Type: vdrapi.DIDCommServiceType,
			}}})

		expectedDIDKey, _ := fingerprint.CreateDIDKey(expected.Value)

		require.NoError(t, err)
		require.NotEmpty(t, result.DIDDocument.Service)
		require.NotEmpty(t, result.DIDDocument.Service[0].RecipientKeys)
		require.Equal(t, expectedDIDKey,
			result.DIDDocument.Service[0].RecipientKeys[0])
	})

	t.Run("inlined recipient keys for legacy didcomm", func(t *testing.T) {
		expected := getSigningKey()
		c, err := New(sProvider)
		require.NoError(t, err)

		result, err := c.Create(
			&did.Doc{VerificationMethod: []did.VerificationMethod{expected}, Service: []did.Service{{
				Type: vdrapi.LegacyServiceType,
			}}})

		require.NoError(t, err)
		require.NotEmpty(t, result.DIDDocument.Service)
		require.NotEmpty(t, result.DIDDocument.Service[0].RecipientKeys)
		require.Equal(t, base58.Encode(expected.Value),
			result.DIDDocument.Service[0].RecipientKeys[0])
	})

	t.Run("create using Service with empty type and bad DefaultServiceType opt (not string)", func(t *testing.T) {
		expected, keyAgreement := getSigningAndKeyAgreementKey(t, false, km)
		c, err := New(sProvider)
		require.NoError(t, err)

		_, err = c.Create(
			&did.Doc{
				VerificationMethod: []did.VerificationMethod{expected},
				Service: []did.Service{{
					Type: "",
				}},
				KeyAgreement: []did.Verification{keyAgreement},
			},
			vdrspi.WithOption(DefaultServiceType, []byte{}))
		require.EqualError(t, err, "create peer DID : defaultServiceType not string")
	})

	t.Run("create using Service with bad store option (not bool)", func(t *testing.T) {
		expected, keyAgreement := getSigningAndKeyAgreementKey(t, false, km)
		c, err := New(sProvider)
		require.NoError(t, err)

		_, err = c.Create(
			&did.Doc{
				VerificationMethod: []did.VerificationMethod{expected},
				Service: []did.Service{{
					Type: "",
				}},
				KeyAgreement: []did.Verification{keyAgreement},
			},
			vdrspi.WithOption("store", []byte{}))
		require.EqualError(t, err, "store opt not boolean")
	})

	t.Run("create using Service with bad (missing) DefaultServiceEndpoint option (not string)", func(t *testing.T) {
		expected, keyAgreement := getSigningAndKeyAgreementKey(t, false, km)
		c, err := New(sProvider)
		require.NoError(t, err)

		_, err = c.Create(
			&did.Doc{
				VerificationMethod: []did.VerificationMethod{expected},
				Service: []did.Service{{
					Type: vdrapi.DIDCommServiceType,
				}},
				KeyAgreement: []did.Verification{keyAgreement},
			})
		require.NoError(t, err, "create peer DID : defaultServiceEndpoint not string")
	})

	t.Run("create using Service with bad DefaultServiceEndpoint option (not string)", func(t *testing.T) {
		expected, keyAgreement := getSigningAndKeyAgreementKey(t, false, km)
		c, err := New(sProvider)
		require.NoError(t, err)

		_, err = c.Create(
			&did.Doc{
				VerificationMethod: []did.VerificationMethod{expected},
				Service: []did.Service{{
					Type: vdrapi.DIDCommServiceType,
				}},
				KeyAgreement: []did.Verification{keyAgreement},
			},
			vdrspi.WithOption(DefaultServiceEndpoint, []byte{}))
		require.EqualError(t, err, "create peer DID : defaultServiceEndpoint not string")
	})

	serviceTypes := []string{vdrapi.DIDCommServiceType, vdrapi.DIDCommV2ServiceType, vdrapi.LegacyServiceType}

	for _, svcType := range serviceTypes {
		t.Run("test success - create using Service with P-256 keys as jsonWebKey2020 with service type: "+svcType,
			func(t *testing.T) {
				expected, keyAgreement := getSigningAndKeyAgreementKey(t, true, km)
				c, err := New(sProvider)
				require.NoError(t, err)

				result, err := c.Create(
					&did.Doc{
						VerificationMethod: []did.VerificationMethod{expected},
						Service: []did.Service{{
							Type: svcType,
						}},
						KeyAgreement: []did.Verification{keyAgreement},
					})

				expectedKey, _ := fingerprint.CreateDIDKey(expected.Value)

				if svcType == vdrapi.DIDCommV2ServiceType {
					expectedKey = keyAgreement.VerificationMethod.ID
				}

				if svcType == vdrapi.LegacyServiceType {
					expectedKey = base58.Encode(expected.Value)
				}

				require.NoError(t, err)
				require.NotEmpty(t, result.DIDDocument.Service)
				require.NotEmpty(t, result.DIDDocument.Service[0].RecipientKeys)
				require.Equal(t, expectedKey,
					result.DIDDocument.Service[0].RecipientKeys[0])
			})
	}
}

func getSigningKey() did.VerificationMethod {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return did.VerificationMethod{Value: pub[:], Type: ed25519VerificationKey2018}
}

func getSigningAndKeyAgreementKey(t *testing.T, useJWK bool, km kmsapi.KeyManager) (did.VerificationMethod, did.Verification) { // nolint:lll
	if !useJWK {
		signingPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		encPub := make([]byte, 32)

		_, err = rand.Read(encPub)
		require.NoError(t, err)

		return did.VerificationMethod{Value: signingPub[:], Type: ed25519VerificationKey2018}, did.Verification{
			VerificationMethod: did.VerificationMethod{Value: encPub, Type: x25519KeyAgreementKey2019},
			Relationship:       did.KeyAgreement,
		}
	}

	crv := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(crv, rand.Reader)
	require.NoError(t, err)

	keyBytes := elliptic.Marshal(crv, privateKey.X, privateKey.Y)
	signingJWK, err := jwkkid.BuildJWK(keyBytes, kmsapi.ECDSAP256TypeIEEEP1363)
	require.NoError(t, err)

	kid, encKeyBytes, err := km.CreateAndExportPubKeyBytes(kmsapi.NISTP256ECDHKWType)
	require.NoError(t, err)

	encryptionJWK, err := jwkkid.BuildJWK(encKeyBytes, kmsapi.NISTP256ECDHKWType)
	require.NoError(t, err)

	signingVM, err := did.NewVerificationMethodFromJWK("", jsonWebKey2020, "", signingJWK)
	require.NoError(t, err)

	kaVM, err := did.NewVerificationMethodFromJWK("#"+kid, jsonWebKey2020, "", encryptionJWK)
	require.NoError(t, err)

	return *signingVM, did.Verification{
		VerificationMethod: *kaVM,
		Relationship:       did.KeyAgreement,
	}
}

type kmsProvider struct {
	store             kmsapi.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kmsapi.Store {
	return k.store
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

func newKMS(t *testing.T, store spi.Provider) kmsapi.KeyManager {
	t.Helper()

	kmsStore, err := kms.NewAriesProviderWrapper(store)
	require.NoError(t, err)

	kmsProv := &kmsProvider{
		store:             kmsStore,
		secretLockService: &noop.NoLock{},
	}

	customKMS, err := localkms.New("local-lock://primary/test/", kmsProv)
	require.NoError(t, err)

	return customKMS
}
