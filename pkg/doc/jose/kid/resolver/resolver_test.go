/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"

	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
)

func TestResolveDIDKey(t *testing.T) {
	didKeyP256 := "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"

	didKeyResolver := &DIDKeyResolver{}

	key, err := didKeyResolver.Resolve(didKeyP256)
	require.NoError(t, err)
	require.NotEmpty(t, key)
	require.Equal(t, commonpb.EllipticCurveType_NIST_P256.String(), key.Curve)
	require.Equal(t, "EC", key.Type)
}

func TestResolveStoreKey(t *testing.T) {
	kid := "key-1"
	expectedKey := &cryptoapi.PublicKey{
		KID:   kid,
		X:     []byte("x"),
		Y:     []byte("y"),
		Curve: "P-521",
		Type:  "EC",
	}

	mKey, err := json.Marshal(expectedKey)
	require.NoError(t, err)

	store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}

	t.Run("resolve success", func(t *testing.T) {
		err = store.Put(kid, mKey)
		require.NoError(t, err)

		storeKeyResolver := &StoreResolver{Store: store}

		key, e := storeKeyResolver.Resolve(kid)
		require.NoError(t, e)
		require.EqualValues(t, expectedKey, key)
	})

	t.Run("resolve fail with Unmarshal error", func(t *testing.T) {
		err = store.Put(kid, []byte("*"))
		require.NoError(t, err)

		storeKeyResolver := &StoreResolver{Store: store}

		key, e := storeKeyResolver.Resolve(kid)
		require.EqualError(t, e, "storeResolver: failed to unmarshal public key from DB: invalid character "+
			"'*' looking for beginning of value")
		require.Empty(t, key)
	})

	t.Run("resolve fail with Get error", func(t *testing.T) {
		getFailErr := "get Fail"
		failStore := &mockstorage.MockStore{ErrGet: errors.New(getFailErr)}
		storeKeyResolver := &StoreResolver{Store: failStore}

		key, e := storeKeyResolver.Resolve(kid)
		require.EqualError(t, e, fmt.Sprintf("storeResolver: failed to resolve kid from store: %s", getFailErr))
		require.Empty(t, key)
	})
}

func TestDIDDocResolverKey(t *testing.T) {
	t.Run("resolve with empty DID doc should fail", func(t *testing.T) {
		docResolver := DIDDocResolver{}
		_, err := docResolver.Resolve("")
		require.EqualError(t, err, "didDocResolver: missing vdr registry")
	})

	t.Run("success - resolve with valid DID doc with X25519 key as KeyAgreement", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "random")
		docResolver := DIDDocResolver{VDRRegistry: &mockvdr.MockVDRegistry{
			ResolveValue: didDoc,
		}}

		pubKey, err := docResolver.Resolve("did:peer:random#key-4")
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
		require.Equal(t, "X25519", pubKey.Curve)
		require.Equal(t, "OKP", pubKey.Type)
		require.EqualValues(t, didDoc.KeyAgreement[0].VerificationMethod.Value, pubKey.X)
	})

	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{
			name:  "success - resolve with valid DID doc with P-256 key as keyAgreement",
			curve: elliptic.P256(),
		},
		{
			name:  "success - resolve with valid DID doc with P-384 key as keyAgreement",
			curve: elliptic.P384(),
		},
		{
			name:  "success - resolve with valid DID doc with P-521 key as keyAgreement",
			curve: elliptic.P521(),
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			didDoc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "random")
			pk, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			jwkKey, err := jwksupport.JWKFromKey(&pk.PublicKey)
			require.NoError(t, err)

			tp, err := jwkKey.Thumbprint(crypto.SHA256)
			require.NoError(t, err)

			kmsKID := base64.RawURLEncoding.EncodeToString(tp)

			vm, err := did.NewVerificationMethodFromJWK(
				didDoc.KeyAgreement[0].VerificationMethod.ID, jsonWebKey2020, didDoc.ID, jwkKey)
			require.NoError(t, err)

			didDoc.KeyAgreement[0].VerificationMethod = *vm

			docResolver := DIDDocResolver{VDRRegistry: &mockvdr.MockVDRegistry{
				ResolveValue: didDoc,
			}}

			pubKey, err := docResolver.Resolve("did:peer:random#key-4")
			require.NoError(t, err)
			require.NotEmpty(t, pubKey)
			require.EqualValues(t, kmsKID, pubKey.KID)
			require.Equal(t, tc.curve.Params().Name, pubKey.Curve)
			require.Equal(t, "EC", pubKey.Type)
			require.EqualValues(t, pk.PublicKey.X.Bytes(), pubKey.X)
			require.EqualValues(t, pk.PublicKey.Y.Bytes(), pubKey.Y)
		})
	}

	t.Run("success - resolve with valid DID doc with X25519 key as JWK in keyAgreement", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "random")

		x25519 := make([]byte, 32)
		_, err := rand.Read(x25519)
		require.NoError(t, err)

		jwkKey, err := jwksupport.JWKFromX25519Key(x25519)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK(
			didDoc.KeyAgreement[0].VerificationMethod.ID, jsonWebKey2020, didDoc.ID, jwkKey)
		require.NoError(t, err)

		didDoc.KeyAgreement[0].VerificationMethod = *vm

		docResolver := DIDDocResolver{VDRRegistry: &mockvdr.MockVDRegistry{
			ResolveValue: didDoc,
		}}

		pubKey, err := docResolver.Resolve("did:peer:random#key-4")
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
		require.Equal(t, "X25519", pubKey.Curve)
		require.Equal(t, "OKP", pubKey.Type)
		require.EqualValues(t, x25519, pubKey.X)

		t.Run("failure resolving with kid missing # key index", func(t *testing.T) {
			_, err = docResolver.Resolve("did:peer:random")
			require.EqualError(t, err, "didDocResolver: kid is not KeyAgreement.ID: 'did:peer:random'")
		})

		t.Run("failure resolving with invalid verification method type", func(t *testing.T) {
			didDoc.KeyAgreement[0].VerificationMethod.Type = "invalid"

			_, err = docResolver.Resolve("did:peer:random#key-4")
			require.EqualError(t, err, "didDocResolver: can't build key from KayAgreement with type: 'invalid'")
		})

		t.Run("failure resolving with invalid JWK key in verification method", func(t *testing.T) {
			var (
				invalidKey  *bbs12381g2pub.PublicKey
				mInvalidKey []byte
				invalidJWK  *jwk.JWK
			)

			invalidKey, _, err = bbs12381g2pub.GenerateKeyPair(sha256.New, []byte{})
			require.NoError(t, err)

			mInvalidKey, err = invalidKey.Marshal()
			require.NoError(t, err)

			invalidJWK, err = jwksupport.PubKeyBytesToJWK(mInvalidKey, kms.BLS12381G2)
			require.NoError(t, err)

			vm, err = did.NewVerificationMethodFromJWK(
				didDoc.KeyAgreement[0].VerificationMethod.ID, jsonWebKey2020, didDoc.ID, invalidJWK)
			require.NoError(t, err)

			didDoc.KeyAgreement[0].VerificationMethod = *vm

			_, err = docResolver.Resolve("did:peer:random#key-4")
			require.EqualError(t, err, "didDocResolver: buildJWKKey: unsupported JWK format: (*bbs12381g2pub.PublicKey)")
		})

		t.Run("failure resolving with invalid X25519 key in verification method", func(t *testing.T) {
			vm = did.NewVerificationMethodFromBytes(didDoc.KeyAgreement[0].VerificationMethod.ID, x25519KeyAgreementKey2019,
				didDoc.ID, bytes.Repeat([]byte{0}, 33)) // 33 is an invalid X25519 public key size.

			didDoc.KeyAgreement[0].VerificationMethod = *vm

			_, err = docResolver.Resolve("did:peer:random#key-4")
			require.EqualError(t, err, "didDocResolver: buildX25519: createKID error:createKID: createX25519KID:"+
				" buildX25519JWK: invalid ECDH X25519 key")
		})
	})
}
