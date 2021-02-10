/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anoncrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	afgjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

func TestAnoncryptPackerSuccess(t *testing.T) {
	k := createKMS(t)

	tests := []struct {
		name    string
		keyType kms.KeyType
		encAlg  afgjose.EncAlg
	}{
		{
			"anoncrypt using NISTP256ECDHKW and AES256-GCM",
			kms.NISTP256ECDHKWType,
			afgjose.A256GCM,
		},
		{
			"anoncrypt using X25519ECDHKW and XChacha20Poly1305",
			kms.X25519ECDHKWType,
			afgjose.XC20P,
		},
		{
			"anoncrypt using NISTP256ECDHKW and XChacha20Poly1305",
			kms.NISTP256ECDHKWType,
			afgjose.XC20P,
		},
		{
			"anoncrypt using X25519ECDHKW and AES256-GCM",
			kms.X25519ECDHKWType,
			afgjose.A256GCM,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		tc := tt
		t.Run(fmt.Sprintf("running %s", tc.name), func(t *testing.T) {
			t.Logf("anoncrypt packing - creating recipient %s keys...", tc.keyType)
			_, recipientsKeys, keyHandles := createRecipientsByKeyType(t, k, 3, tc.keyType)

			cryptoSvc, err := tinkcrypto.New()
			require.NoError(t, err)

			anonPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256GCM)
			require.NoError(t, err)

			origMsg := []byte("secret message")
			ct, err := anonPacker.Pack(origMsg, nil, recipientsKeys)
			require.NoError(t, err)

			jweStr, err := prettyPrint(ct)
			require.NoError(t, err)
			t.Logf("* anoncrypt JWE: %s", jweStr)

			msg, err := anonPacker.Unpack(ct)
			require.NoError(t, err)

			recKey, err := exportPubKeyBytes(keyHandles[0])
			require.NoError(t, err)

			require.EqualValues(t, &transport.Envelope{Message: origMsg, ToKey: recKey}, msg)

			// try with only 1 recipient
			ct, err = anonPacker.Pack(origMsg, nil, [][]byte{recipientsKeys[0]})
			require.NoError(t, err)

			t.Logf("* anoncrypt JWE Compact seriliazation (using first recipient only): %s", ct)

			jweJSON, err := afgjose.Deserialize(string(ct))
			require.NoError(t, err)

			jweStr, err = jweJSON.FullSerialize(json.Marshal)
			require.NoError(t, err)
			t.Logf("* anoncrypt Flattened JWE JSON seriliazation (using first recipient only): %s", jweStr)

			msg, err = anonPacker.Unpack(ct)
			require.NoError(t, err)

			require.EqualValues(t, &transport.Envelope{Message: origMsg, ToKey: recKey}, msg)

			require.Equal(t, encodingType, anonPacker.EncodingType())
		})
	}
}

func TestAnoncryptPackerSuccessWithDifferentCurvesSuccess(t *testing.T) {
	k := createKMS(t)
	_, recipientsKey1, keyHandles1 := createRecipients(t, k, 1)
	_, recipientsKey2, _ := createRecipientsByKeyType(t, k, 1, kms.NISTP384ECDHKW)
	_, recipientsKey3, _ := createRecipientsByKeyType(t, k, 1, kms.NISTP521ECDHKW)

	recipientsKeys := make([][]byte, 3)
	recipientsKeys[0] = make([]byte, len(recipientsKey1[0]))
	recipientsKeys[1] = make([]byte, len(recipientsKey2[0]))
	recipientsKeys[2] = make([]byte, len(recipientsKey3[0]))

	copy(recipientsKeys[0], recipientsKey1[0])
	copy(recipientsKeys[1], recipientsKey2[0])
	copy(recipientsKeys[2], recipientsKey3[0])

	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	anonPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256GCM)
	require.NoError(t, err)

	origMsg := []byte("secret message")
	ct, err := anonPacker.Pack(origMsg, nil, recipientsKeys)
	require.NoError(t, err)

	t.Logf("anoncrypt JWE: %s", ct)

	msg, err := anonPacker.Unpack(ct)
	require.NoError(t, err)

	recKey, err := exportPubKeyBytes(keyHandles1[0])
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{Message: origMsg, ToKey: recKey}, msg)

	// try with only 1 recipient
	ct, err = anonPacker.Pack(origMsg, nil, [][]byte{recipientsKeys[0]})
	require.NoError(t, err)

	msg, err = anonPacker.Unpack(ct)
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{Message: origMsg, ToKey: recKey}, msg)

	require.Equal(t, encodingType, anonPacker.EncodingType())
}

func TestAnoncryptPackerFail(t *testing.T) {
	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	t.Run("new Pack fail with nil kms", func(t *testing.T) {
		_, err = New(newMockProvider(nil, cryptoSvc), afgjose.A256GCM)
		require.EqualError(t, err, "anoncrypt: failed to create packer because KMS is empty")
	})

	k := createKMS(t)
	_, recipientsKeys, _ := createRecipients(t, k, 10)
	origMsg := []byte("secret message")
	anonPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256GCM)
	require.NoError(t, err)

	t.Run("pack fail with empty recipients keys", func(t *testing.T) {
		_, err = anonPacker.Pack(origMsg, nil, nil)
		require.EqualError(t, err, "anoncrypt Pack: empty recipientsPubKeys")
	})

	t.Run("pack fail with invalid recipients keys", func(t *testing.T) {
		_, err = anonPacker.Pack(origMsg, nil, [][]byte{[]byte("invalid")})
		require.EqualError(t, err, "anoncrypt Pack: failed to convert recipient keys: invalid character 'i' "+
			"looking for beginning of value")
	})

	t.Run("pack fail with invalid encAlg", func(t *testing.T) {
		invalidAlg := "invalidAlg"
		invalidAnonPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.EncAlg(invalidAlg))
		require.NoError(t, err)

		_, err = invalidAnonPacker.Pack(origMsg, nil, recipientsKeys)
		require.EqualError(t, err, fmt.Sprintf("anoncrypt Pack: failed to new JWEEncrypt instance: encryption"+
			" algorithm '%s' not supported", invalidAlg))
	})

	t.Run("pack success but unpack fails with invalid payload", func(t *testing.T) {
		validAnonPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256GCM)
		require.NoError(t, err)

		_, err = validAnonPacker.Pack(origMsg, nil, recipientsKeys)
		require.NoError(t, err)

		_, err = validAnonPacker.Unpack([]byte("invalid jwe envelope"))
		require.EqualError(t, err, "anoncrypt Unpack: failed to deserialize JWE message: invalid compact "+
			"JWE: it must have five parts")
	})

	t.Run("pack success but unpack fails with missing keyID in protectedHeader", func(t *testing.T) {
		validAnonPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256GCM)
		require.NoError(t, err)

		ct, err := validAnonPacker.Pack(origMsg, nil, [][]byte{recipientsKeys[0]})
		require.NoError(t, err)

		jwe, err := afgjose.Deserialize(string(ct))
		require.NoError(t, err)

		delete(jwe.ProtectedHeaders, afgjose.HeaderKeyID)

		newCT, err := jwe.CompactSerialize(json.Marshal)
		require.NoError(t, err)

		_, err = validAnonPacker.Unpack([]byte(newCT))
		require.EqualError(t, err, "anoncrypt Unpack: single recipient missing 'KID' in jwe.ProtectHeaders")
	})

	t.Run("pack success but unpack fails with missing kid in kms", func(t *testing.T) {
		kids, newRecKeys, _ := createRecipients(t, k, 2)
		validAnonPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256GCM)
		require.NoError(t, err)

		ct, err := validAnonPacker.Pack(origMsg, nil, newRecKeys)
		require.NoError(t, err)

		// rotate keys to update keyID and force a failure
		_, _, err = k.Rotate(kms.NISTP256ECDHKWType, kids[0])
		require.NoError(t, err)

		_, _, err = k.Rotate(kms.NISTP256ECDHKWType, kids[1])
		require.NoError(t, err)

		_, err = validAnonPacker.Unpack(ct)
		require.EqualError(t, err, "anoncrypt Unpack: no matching recipient in envelope")
	})
}

// createRecipients and return their public key and keyset.Handle.
func createRecipients(t *testing.T, k *localkms.LocalKMS, recipientsCount int) ([]string, [][]byte, []*keyset.Handle) {
	return createRecipientsByKeyType(t, k, recipientsCount, kms.NISTP256ECDHKW)
}

func createRecipientsByKeyType(t *testing.T, k *localkms.LocalKMS, recipientsCount int,
	kt kms.KeyType) ([]string, [][]byte, []*keyset.Handle) {
	t.Helper()

	var (
		r    [][]byte
		rKH  []*keyset.Handle
		kids []string
	)

	for i := 0; i < recipientsCount; i++ {
		kid, marshalledPubKey, kh := createAndMarshalKeyByKeyType(t, k, kt)

		r = append(r, marshalledPubKey)
		rKH = append(rKH, kh)
		kids = append(kids, kid)
	}

	return kids, r, rKH
}

// createAndMarshalKeyByKeyType creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createAndMarshalKeyByKeyType(t *testing.T, k *localkms.LocalKMS, kt kms.KeyType) (string, []byte, *keyset.Handle) {
	t.Helper()

	kid, keyHandle, err := k.Create(kt)
	require.NoError(t, err)

	kh, ok := keyHandle.(*keyset.Handle)
	require.True(t, ok)

	pubKeyBytes, err := exportPubKeyBytes(kh)
	require.NoError(t, err)

	key := &cryptoapi.PublicKey{}
	err = json.Unmarshal(pubKeyBytes, key)
	require.NoError(t, err)

	key.KID = kid
	mKey, err := json.Marshal(key)
	require.NoError(t, err)

	printKey(t, mKey, kid)

	return kid, mKey, kh
}

func printKey(t *testing.T, mPubKey []byte, kid string) {
	t.Helper()

	pubKey := new(cryptoapi.PublicKey)
	err := json.Unmarshal(mPubKey, pubKey)
	require.NoError(t, err)

	switch pubKey.Type {
	case ecdhpb.KeyType_EC.String():
		t.Logf("** EC key: %s, kid: %s", getPrintedECPubKey(t, pubKey), kid)
	case ecdhpb.KeyType_OKP.String():
		t.Logf("** X25519 key: %s, kid: %s", getPrintedX25519PubKey(t, pubKey), kid)
	default:
		t.Errorf("not supported key type: %s", pubKey.Type)
	}
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func getPrintedECPubKey(t *testing.T, pubKey *cryptoapi.PublicKey) string {
	crv, err := hybrid.GetCurve(pubKey.Curve)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key: &ecdsa.PublicKey{
			Curve: crv,
			X:     new(big.Int).SetBytes(pubKey.X),
			Y:     new(big.Int).SetBytes(pubKey.Y),
		},
	}

	jwkByte, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return jwkStr
}

func getPrintedX25519PubKey(t *testing.T, pubKeyType *cryptoapi.PublicKey) string {
	jwk := jose.JSONWebKey{
		Key: ed25519.PublicKey(pubKeyType.X),
	}

	jwkByte, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return strings.Replace(jwkStr, "Ed25519", "X25519", 1)
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p := mockkms.NewProviderForKMS(mockstorage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://test/key/uri", p)
	require.NoError(t, err)

	return k
}

func newMockProvider(customKMS kms.KeyManager, customCrypto cryptoapi.Crypto) *mockprovider.Provider {
	return &mockprovider.Provider{
		KMSValue:    customKMS,
		CryptoValue: customCrypto,
	}
}
