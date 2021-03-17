/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	afgjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/store/wrapper/prefix"
	spilog "github.com/hyperledger/aries-framework-go/spi/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestAuthryptPackerSuccess(t *testing.T) {
	k := createKMS(t)

	tests := []struct {
		name    string
		keyType kms.KeyType
		encAlg  afgjose.EncAlg
		cty     string
	}{
		{
			name:    "anoncrypt using NISTP256ECDHKW and AES256-GCM",
			keyType: kms.NISTP256ECDHKWType,
			encAlg:  afgjose.A256GCM,
			cty:     packer.ContentEncodingTypeV2,
		},
		{
			name:    "anoncrypt using X25519ECDHKW and XChacha20Poly1305",
			keyType: kms.X25519ECDHKWType,
			encAlg:  afgjose.XC20P,
			cty:     packer.ContentEncodingTypeV2,
		},
		{
			name:    "anoncrypt using NISTP256ECDHKW and XChacha20Poly1305",
			keyType: kms.NISTP256ECDHKWType,
			encAlg:  afgjose.XC20P,
			cty:     packer.ContentEncodingTypeV2,
		},
		{
			name:    "anoncrypt using X25519ECDHKW and AES256-GCM",
			keyType: kms.X25519ECDHKWType,
			encAlg:  afgjose.A256GCM,
			cty:     packer.ContentEncodingTypeV2,
		},
		{
			name:    "anoncrypt using NISTP256ECDHKW and AES256-GCM without cty",
			keyType: kms.NISTP256ECDHKWType,
			encAlg:  afgjose.A256GCM,
		},
		{
			name:    "anoncrypt using X25519ECDHKW and XChacha20Poly1305 without cty",
			keyType: kms.X25519ECDHKWType,
			encAlg:  afgjose.XC20P,
		},
		{
			name:    "anoncrypt using NISTP256ECDHKW and XChacha20Poly1305 without cty",
			keyType: kms.NISTP256ECDHKWType,
			encAlg:  afgjose.XC20P,
		},
		{
			name:    "anoncrypt using X25519ECDHKW and AES256-GCM without cty",
			keyType: kms.X25519ECDHKWType,
			encAlg:  afgjose.A256GCM,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		tc := tt
		t.Run(fmt.Sprintf("running %s", tc.name), func(t *testing.T) {
			t.Logf("authcrypt packing - creating sender %s key...", tc.keyType)
			skid, senderKey, _ := createAndMarshalKeyByKeyType(t, k, tc.keyType)

			t.Logf("authcrypt packing - creating recipient %s keys...", tc.keyType)
			_, recipientsKeys, keyHandles := createRecipientsByKeyType(t, k, 3, tc.keyType)

			thirdPartyKeyStore := make(map[string]mockstorage.DBEntry)
			mockStoreProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
				Store: thirdPartyKeyStore,
			}}

			log.SetLevel("aries-framework/pkg/didcomm/packer/authcrypt", spilog.DEBUG)

			cryptoSvc, err := tinkcrypto.New()
			require.NoError(t, err)

			authPacker, err := New(newMockProvider(mockStoreProvider, k, cryptoSvc), tc.encAlg)
			require.NoError(t, err)

			// add sender key in thirdPartyKS (prep step before Authcrypt.Pack()/Unpack())
			fromWrappedKID := prefix.StorageKIDPrefix + skid
			thirdPartyKeyStore[fromWrappedKID] = mockstorage.DBEntry{Value: senderKey}

			origMsg := []byte("secret message")
			ct, err := authPacker.Pack(tc.cty, origMsg, []byte(skid), recipientsKeys)
			require.NoError(t, err)

			jweStr, err := prettyPrint(ct)
			require.NoError(t, err)
			t.Logf("* authcrypt JWE: %s", jweStr)

			msg, err := authPacker.Unpack(ct)
			require.NoError(t, err)

			recKey, err := exportPubKeyBytes(keyHandles[0])
			require.NoError(t, err)

			require.EqualValues(t, &transport.Envelope{CTY: tc.cty, Message: origMsg, ToKey: recKey}, msg)

			jweJSON, err := afgjose.Deserialize(string(ct))
			require.NoError(t, err)

			verifyJWETypes(t, tc.cty, jweJSON.ProtectedHeaders)

			// try with only 1 recipient to force compact JWE serialization
			ct, err = authPacker.Pack(tc.cty, origMsg, []byte(skid), [][]byte{recipientsKeys[0]})
			require.NoError(t, err)

			t.Logf("* authcrypt JWE Compact seriliazation (using first recipient only): %s", ct)

			jweJSON, err = afgjose.Deserialize(string(ct))
			require.NoError(t, err)

			jweStr, err = jweJSON.FullSerialize(json.Marshal)
			require.NoError(t, err)
			t.Logf("* authcrypt Flattened JWE JSON seriliazation (using first recipient only): %s", jweStr)

			msg, err = authPacker.Unpack(ct)
			require.NoError(t, err)

			require.EqualValues(t, &transport.Envelope{CTY: tc.cty, Message: origMsg, ToKey: recKey}, msg)

			verifyJWETypes(t, tc.cty, jweJSON.ProtectedHeaders)
		})
	}
}

func verifyJWETypes(t *testing.T, cty string, jweHeader afgjose.Headers) {
	encodingType, ok := jweHeader.Type()
	require.True(t, ok)

	require.Equal(t, packer.EnvelopeEncodingTypeV2, encodingType)

	contentType, ok := jweHeader.ContentType()
	require.True(t, contentType == "" || contentType != "" && ok)

	require.Equal(t, cty, contentType)
}

func TestAuthryptPackerUsingKeysWithDifferentCurvesSuccess(t *testing.T) {
	k := createKMS(t)
	_, recipientsKey1, keyHandles1 := createRecipients(t, k, 1)
	// since authcrypt does ECDH kw using the sender key, the recipient keys must be on the same curve (for NIST P keys)
	// and the same key type (for NIST P / X25519 keys) as the sender's.
	// this is why recipient keys with different curves/type are not supported for authcrypt.
	_, recipientsKey2, _ := createRecipients(t, k, 1) // can't create key with kms.NISTP384ECDHKW
	_, recipientsKey3, _ := createRecipients(t, k, 1) // can't create key with kms.NISTP521ECDHKW

	recipientsKeys := make([][]byte, 3)
	recipientsKeys[0] = make([]byte, len(recipientsKey1[0]))
	recipientsKeys[1] = make([]byte, len(recipientsKey2[0]))
	recipientsKeys[2] = make([]byte, len(recipientsKey3[0]))

	copy(recipientsKeys[0], recipientsKey1[0])
	copy(recipientsKeys[1], recipientsKey2[0])
	copy(recipientsKeys[2], recipientsKey3[0])

	cty := packer.ContentEncodingTypeV2

	skid, senderKey, _ := createAndMarshalKey(t, k)

	thirdPartyKeyStore := make(map[string]mockstorage.DBEntry)
	mockStoreProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: thirdPartyKeyStore,
	}}

	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	authPacker, err := New(newMockProvider(mockStoreProvider, k, cryptoSvc), afgjose.A256GCM)
	require.NoError(t, err)

	// add sender key in thirdPartyKS (prep step before Authcrypt.Pack()/Unpack())
	fromWrappedKID := prefix.StorageKIDPrefix + skid
	thirdPartyKeyStore[fromWrappedKID] = mockstorage.DBEntry{Value: senderKey}

	origMsg := []byte("secret message")
	ct, err := authPacker.Pack(cty, origMsg, []byte(skid), recipientsKeys)
	require.NoError(t, err)

	t.Logf("authcrypt JWE: %s", ct)

	msg, err := authPacker.Unpack(ct)
	require.NoError(t, err)

	recKey, err := exportPubKeyBytes(keyHandles1[0])
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{CTY: cty, Message: origMsg, ToKey: recKey}, msg)

	// try with only 1 recipient
	ct, err = authPacker.Pack(cty, origMsg, []byte(skid), [][]byte{recipientsKeys[0]})
	require.NoError(t, err)

	msg, err = authPacker.Unpack(ct)
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{CTY: cty, Message: origMsg, ToKey: recKey}, msg)

	jweJSON, err := afgjose.Deserialize(string(ct))
	require.NoError(t, err)

	verifyJWETypes(t, cty, jweJSON.ProtectedHeaders)
}

func TestAuthcryptPackerFail(t *testing.T) {
	cty := packer.ContentEncodingTypeV2

	k := createKMS(t)

	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	skid, senderKey, _ := createAndMarshalKey(t, k)

	t.Run("new Pack fail with nil thirdPartyKS provider", func(t *testing.T) {
		_, err = New(newMockProvider(nil, k, cryptoSvc), afgjose.A256GCM)
		require.EqualError(t, err, "authcrypt: failed to create packer because StorageProvider is empty")
	})

	t.Run("new Pack fail with bad thirdPartyKS provider", func(t *testing.T) {
		badStoreProvider := &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("failed to open thirdPartyKS"),
			FailNamespace:      ThirdPartyKeysDB,
		}

		_, err = New(newMockProvider(badStoreProvider, k, cryptoSvc), afgjose.A256GCM)
		require.EqualError(t, err, "authcrypt: failed to open store for name space thirdpartykeysdb")
	})

	mockStoreMap := make(map[string]mockstorage.DBEntry)
	mockStoreProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: mockStoreMap,
	}}

	t.Run("new Pack fail with nil kms", func(t *testing.T) {
		_, err = New(newMockProvider(mockStoreProvider, nil, cryptoSvc), afgjose.A256GCM)
		require.EqualError(t, err, "authcrypt: failed to create packer because KMS is empty")
	})

	_, recipientsKeys, _ := createRecipients(t, k, 10)
	origMsg := []byte("secret message")
	authPacker, err := New(newMockProvider(mockStoreProvider, k, cryptoSvc), afgjose.A256GCM)
	require.NoError(t, err)

	mockStoreMap[skid] = mockstorage.DBEntry{Value: senderKey}
	skidB := []byte(skid)

	t.Run("pack fail with empty recipients keys", func(t *testing.T) {
		_, err = authPacker.Pack(cty, origMsg, nil, nil)
		require.EqualError(t, err, "authcrypt Pack: empty recipientsPubKeys")
	})

	t.Run("pack fail with invalid recipients keys", func(t *testing.T) {
		_, err = authPacker.Pack(cty, origMsg, nil, [][]byte{[]byte("invalid")})
		require.EqualError(t, err, "authcrypt Pack: failed to convert recipient keys: invalid character 'i' "+
			"looking for beginning of value")
	})

	t.Run("pack fail with invalid encAlg", func(t *testing.T) {
		invalidAlg := "invalidAlg"
		invalidAuthPacker, err := New(newMockProvider(mockStoreProvider, k, cryptoSvc), afgjose.EncAlg(invalidAlg))
		require.NoError(t, err)

		_, err = invalidAuthPacker.Pack(cty, origMsg, skidB, recipientsKeys)
		require.EqualError(t, err, fmt.Sprintf("authcrypt Pack: failed to new JWEEncrypt instance: encryption"+
			" algorithm '%s' not supported", invalidAlg))
	})

	t.Run("pack fail with KMS can't get sender key", func(t *testing.T) {
		badKMSStoreProvider := mockstorage.NewCustomMockStoreProvider(
			&mockstorage.MockStore{ErrGet: errors.New("bad fake key ID")})
		p := mockkms.NewProviderForKMS(badKMSStoreProvider, &noop.NoLock{})

		badKMS, err := localkms.New("local-lock://test/key/uri", p)
		require.NoError(t, err)

		badAuthPacker, err := New(newMockProvider(mockStoreProvider, badKMS, cryptoSvc), afgjose.A256GCM)
		require.NoError(t, err)

		_, err = badAuthPacker.Pack(cty, origMsg, skidB, recipientsKeys)
		require.Contains(t, fmt.Sprintf("%v", err), "bad fake key ID")
	})

	t.Run("pack success but unpack fails with invalid payload", func(t *testing.T) {
		validAuthPacker, err := New(newMockProvider(mockStoreProvider, k, cryptoSvc), afgjose.A256GCM)
		require.NoError(t, err)

		_, err = validAuthPacker.Pack(cty, origMsg, skidB, recipientsKeys)
		require.NoError(t, err)

		_, err = validAuthPacker.Unpack([]byte("invalid jwe envelope"))
		require.EqualError(t, err, "authcrypt Unpack: failed to deserialize JWE message: invalid compact "+
			"JWE: it must have five parts")
	})

	t.Run("pack success but unpack fails with missing keyID in protectedHeader", func(t *testing.T) {
		validAuthPacker, err := New(newMockProvider(mockStoreProvider, k, cryptoSvc), afgjose.A256GCM)
		require.NoError(t, err)

		ct, err := validAuthPacker.Pack(cty, origMsg, skidB, [][]byte{recipientsKeys[0]})
		require.NoError(t, err)

		jwe, err := afgjose.Deserialize(string(ct))
		require.NoError(t, err)

		delete(jwe.ProtectedHeaders, afgjose.HeaderKeyID)

		newCT, err := jwe.CompactSerialize(json.Marshal)
		require.NoError(t, err)

		_, err = validAuthPacker.Unpack([]byte(newCT))
		require.EqualError(t, err, "authcrypt Unpack: single recipient missing 'KID' in jwe.ProtectHeaders")
	})

	t.Run("pack success but unpack fails with missing kid in kms", func(t *testing.T) {
		kids, newRecKeys, _ := createRecipients(t, k, 2)
		validAuthPacker, err := New(newMockProvider(mockStoreProvider, k, cryptoSvc), afgjose.A256GCM)
		require.NoError(t, err)

		ct, err := validAuthPacker.Pack(cty, origMsg, skidB, newRecKeys)
		require.NoError(t, err)

		// rotate keys to update keyID and force a failure
		_, _, err = k.Rotate(kms.NISTP256ECDHKWType, kids[0])
		require.NoError(t, err)

		_, _, err = k.Rotate(kms.NISTP256ECDHKWType, kids[1])
		require.NoError(t, err)

		_, err = validAuthPacker.Unpack(ct)
		require.EqualError(t, err, "authcrypt Unpack: no matching recipient in envelope")
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

// createAndMarshalKey creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createAndMarshalKey(t *testing.T, k *localkms.LocalKMS) (string, []byte, *keyset.Handle) {
	return createAndMarshalKeyByKeyType(t, k, kms.NISTP256ECDHKWType)
}

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

func newMockProvider(customStoreProvider storage.Provider, customKMS kms.KeyManager,
	customCrypto cryptoapi.Crypto) *mockprovider.Provider {
	return &mockprovider.Provider{
		KMSValue:             customKMS,
		StorageProviderValue: customStoreProvider,
		CryptoValue:          customCrypto,
	}
}
