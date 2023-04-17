/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang/protobuf/proto"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	afgjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/kmsdidkey"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	spilog "github.com/hyperledger/aries-framework-go/spi/log"
)

func TestAuthcryptPackerSuccess(t *testing.T) {
	k := createKMS(t)

	tests := []struct {
		name    string
		keyType kms.KeyType
		encAlg  afgjose.EncAlg
		cty     string
	}{
		{
			name:    "authcrypt using NISTP256ECDHKW and AES128CBC+HMAC-SHA256",
			keyType: kms.NISTP256ECDHKWType,
			encAlg:  afgjose.A128CBCHS256,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using NISTP384ECDHKW and AES192CBC+HMAC-SHA384",
			keyType: kms.NISTP384ECDHKWType,
			encAlg:  afgjose.A192CBCHS384,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using NISTP521ECDHKW and AES256CBC+HMAC-SHA512",
			keyType: kms.NISTP521ECDHKWType,
			encAlg:  afgjose.A256CBCHS512,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using X25519ECDHKWType and AES128CBC+HMAC-SHA256",
			keyType: kms.X25519ECDHKWType,
			encAlg:  afgjose.A128CBCHS256ALG,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using NISTP256ECDHKW and XChacha20Poly1305",
			keyType: kms.NISTP256ECDHKW,
			encAlg:  afgjose.XC20P,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using NISTP384ECDHKW and XChacha20Poly1305",
			keyType: kms.NISTP384ECDHKW,
			encAlg:  afgjose.XC20P,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using NISTP521ECDHKW and XChacha20Poly1305",
			keyType: kms.NISTP521ECDHKW,
			encAlg:  afgjose.XC20P,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using X25519ECDHKWType and XChacha20Poly1305",
			keyType: kms.X25519ECDHKWType,
			encAlg:  afgjose.XC20P,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using NISTP256ECDHKW and AES192CBC+HMAC-SHA384",
			keyType: kms.NISTP256ECDHKWType,
			encAlg:  afgjose.A192CBCHS384,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using X25519ECDHKW and XChacha20Poly1305 without cty",
			keyType: kms.X25519ECDHKWType,
			encAlg:  afgjose.XC20P,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using NISTP256ECDHKW and XChacha20Poly1305 without cty",
			keyType: kms.NISTP256ECDHKWType,
			encAlg:  afgjose.XC20P,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "authcrypt using X25519ECDHKW and AES256-CBC+SHA512",
			keyType: kms.X25519ECDHKWType,
			encAlg:  afgjose.A256CBCHS512,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		tc := tt
		t.Run(fmt.Sprintf("running %s", tc.name), func(t *testing.T) {
			t.Logf("authcrypt packing - creating kid %s key...", tc.keyType)
			skid, sDIDKey, mSenderPubKey, _ := createAndMarshalKeyByKeyType(t, k, tc.keyType)

			t.Logf("authcrypt packing - creating recipient %s keys...", tc.keyType)
			_, recDIDKeys, recipientsKeys, keyHandles := createRecipientsByKeyType(t, k, 3, tc.keyType)

			log.SetLevel("aries-framework/pkg/didcomm/packer/authcrypt", spilog.DEBUG)

			cryptoSvc, err := tinkcrypto.New()
			require.NoError(t, err)

			authPacker, err := New(newMockProvider(k, cryptoSvc), tc.encAlg)
			require.NoError(t, err)

			origMsg := []byte("secret message")
			ct, err := authPacker.Pack(tc.cty, origMsg, []byte(skid+"."+sDIDKey), recipientsKeys)
			require.NoError(t, err)

			jweStr, err := prettyPrint(ct)
			require.NoError(t, err)
			t.Logf("* authcrypt JWE: %s", jweStr)

			msg, err := authPacker.Unpack(ct)
			require.NoError(t, err)

			recKey, err := exportPubKeyBytes(keyHandles[0], recDIDKeys[0])
			require.NoError(t, err)

			senderPubKey := &cryptoapi.PublicKey{}

			err = json.Unmarshal(mSenderPubKey, senderPubKey)
			require.NoError(t, err)

			senderPubKey.KID = sDIDKey // match packer value.

			mSenderPubKey, err = json.Marshal(senderPubKey)
			require.NoError(t, err)

			require.EqualValues(t, &transport.Envelope{Message: origMsg, FromKey: mSenderPubKey, ToKey: recKey}, msg)

			jweJSON, err := afgjose.Deserialize(string(ct))
			require.NoError(t, err)

			verifyJWETypes(t, tc.cty, jweJSON.ProtectedHeaders)

			// try with only 1 recipient to force compact JWE serialization
			ct, err = authPacker.Pack(tc.cty, origMsg, []byte(skid+"."+sDIDKey), [][]byte{recipientsKeys[0]})
			require.NoError(t, err)

			t.Logf("* authcrypt JWE Compact serialization (using first recipient only): %s", ct)

			jweJSON, err = afgjose.Deserialize(string(ct))
			require.NoError(t, err)

			jweStr, err = jweJSON.FullSerialize(json.Marshal)
			require.NoError(t, err)
			t.Logf("* authcrypt Flattened JWE JSON serialization (using first recipient only): %s", jweStr)

			msg, err = authPacker.Unpack(ct)
			require.NoError(t, err)

			require.EqualValues(t, &transport.Envelope{Message: origMsg, FromKey: mSenderPubKey, ToKey: recKey}, msg)

			verifyJWETypes(t, tc.cty, jweJSON.ProtectedHeaders)
		})
	}
}

func verifyJWETypes(t *testing.T, cty string, jweHeader afgjose.Headers) {
	encodingType, ok := jweHeader.Type()
	require.True(t, ok)

	require.Equal(t, transport.MediaTypeV2EncryptedEnvelope, encodingType)

	contentType, ok := jweHeader.ContentType()
	require.True(t, contentType == "" || contentType != "" && ok)

	require.Equal(t, cty, contentType)
}

func TestAuthcryptPackerUsingKeysWithDifferentCurvesSuccess(t *testing.T) {
	k := createKMS(t)
	_, recDIDKeys, recipientsKey1, keyHandles1 := createRecipients(t, k, 1)
	// since authcrypt does ECDH kw using the sender key, the recipient keys must be on the same curve (for NIST P keys)
	// and the same key type (for NIST P / X25519 keys) as the sender's.
	// this is why recipient keys with different curves/type are not supported for authcrypt.
	//nolint:dogsled
	_, _, recipientsKey2, _ := createRecipients(t, k, 1) // can't create key with kms.NISTP384ECDHKW
	//nolint:dogsled
	_, _, recipientsKey3, _ := createRecipients(t, k, 1) // can't create key with kms.NISTP521ECDHKW

	recipientsKeys := make([][]byte, 3)
	recipientsKeys[0] = make([]byte, len(recipientsKey1[0]))
	recipientsKeys[1] = make([]byte, len(recipientsKey2[0]))
	recipientsKeys[2] = make([]byte, len(recipientsKey3[0]))

	copy(recipientsKeys[0], recipientsKey1[0])
	copy(recipientsKeys[1], recipientsKey2[0])
	copy(recipientsKeys[2], recipientsKey3[0])

	cty := transport.MediaTypeV1PlaintextPayload

	skid, sDIDKey, mSenderPubKey, _ := createAndMarshalKey(t, k)

	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	authPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256CBCHS512)
	require.NoError(t, err)

	origMsg := []byte("secret message")
	ct, err := authPacker.Pack(cty, origMsg, []byte(skid+"."+sDIDKey), recipientsKeys)
	require.NoError(t, err)

	t.Logf("authcrypt JWE: %s", ct)

	msg, err := authPacker.Unpack(ct)
	require.NoError(t, err)

	recKey, err := exportPubKeyBytes(keyHandles1[0], recDIDKeys[0])
	require.NoError(t, err)

	senderPubKey := &cryptoapi.PublicKey{}

	err = json.Unmarshal(mSenderPubKey, senderPubKey)
	require.NoError(t, err)

	senderPubKey.KID = sDIDKey // match packer value.

	mSenderPubKey, err = json.Marshal(senderPubKey)
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{
		Message: origMsg,
		FromKey: mSenderPubKey,
		ToKey:   recKey,
	}, msg)

	// try with only 1 recipient
	ct, err = authPacker.Pack(cty, origMsg, []byte(skid+"."+sDIDKey), [][]byte{recipientsKeys[0]})
	require.NoError(t, err)

	msg, err = authPacker.Unpack(ct)
	require.NoError(t, err)

	senderPubKey = &cryptoapi.PublicKey{}

	err = json.Unmarshal(mSenderPubKey, senderPubKey)
	require.NoError(t, err)

	senderPubKey.KID = sDIDKey // match packer value.

	mSenderPubKey, err = json.Marshal(senderPubKey)
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{
		Message: origMsg,
		FromKey: mSenderPubKey,
		ToKey:   recKey,
	}, msg)

	jweJSON, err := afgjose.Deserialize(string(ct))
	require.NoError(t, err)

	verifyJWETypes(t, cty, jweJSON.ProtectedHeaders)
}

func TestAuthcryptPackerFail(t *testing.T) {
	cty := transport.MediaTypeV1PlaintextPayload
	k := createKMS(t)

	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	skid, sDIDKey, _, _ := createAndMarshalKey(t, k)
	skidB := []byte(skid + "." + sDIDKey)

	t.Run("new Pack fail with nil crypto service", func(t *testing.T) {
		_, err = New(newMockProvider(k, nil), afgjose.A128CBCHS256)
		require.EqualError(t, err, "authcrypt: failed to create packer because crypto service is empty")
	})

	t.Run("new Pack fail with invalid encryption algorithm", func(t *testing.T) {
		_, err = New(newMockProvider(k, cryptoSvc), "invalidAlg")
		require.EqualError(t, err, "authcrypt: unsupported content encrytpion algorithm: invalidAlg")
	})

	t.Run("new Pack fail with nil kms", func(t *testing.T) {
		_, err = New(newMockProvider(nil, cryptoSvc), afgjose.A128CBCHS256)
		require.EqualError(t, err, "authcrypt: failed to create packer because KMS is empty")
	})

	_, _, recipientsKeys, _ := createRecipients(t, k, 10) //nolint:dogsled
	origMsg := []byte("secret message")
	authPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256CBCHS512)
	require.NoError(t, err)

	t.Run("unpack fail with bad recipient key", func(t *testing.T) {
		_, _, keys, _ := createRecipients(t, k, 1)
		keys[0] = []byte(strings.Replace(string(keys[0]), "did:key:", "invalid", 1))
		var ct []byte
		ct, err = authPacker.Pack(cty, origMsg, []byte(skid+"."+sDIDKey), keys)
		require.NoError(t, err)
		_, err = authPacker.Unpack(ct)
		require.Contains(t, err.Error(), "invalid kid format, must be a did:key")
	})

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
		invalidAuthPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A256CBCHS512)
		require.NoError(t, err)

		invalidAuthPacker.encAlg = afgjose.EncAlg(invalidAlg)
		_, err = invalidAuthPacker.Pack(cty, origMsg, skidB, recipientsKeys)
		require.EqualError(t, err, fmt.Sprintf("authcrypt Pack: failed to new JWEEncrypt instance: encryption"+
			" algorithm '%s' not supported", invalidAlg))
	})

	t.Run("pack fail with KMS can't get kid key", func(t *testing.T) {
		badKMSStoreProvider := mockstorage.NewCustomMockStoreProvider(
			&mockstorage.MockStore{ErrGet: errors.New("bad fake key ID")})
		p, err := mockkms.NewProviderForKMS(badKMSStoreProvider, &noop.NoLock{})
		require.NoError(t, err)

		badKMS, err := localkms.New("local-lock://test/key/uri", p)
		require.NoError(t, err)

		badAuthPacker, err := New(newMockProvider(badKMS, cryptoSvc), afgjose.A128CBCHS256)
		require.NoError(t, err)

		_, err = badAuthPacker.Pack(cty, origMsg, skidB, recipientsKeys)
		require.Contains(t, fmt.Sprintf("%v", err), "bad fake key ID")
	})

	t.Run("pack success but unpack fails with invalid payload format", func(t *testing.T) {
		validAuthPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A192CBCHS384)
		require.NoError(t, err)

		_, err = validAuthPacker.Pack(cty, origMsg, skidB, recipientsKeys)
		require.NoError(t, err)

		_, err = validAuthPacker.Unpack([]byte("invalid jwe envelope"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "authcrypt Unpack: failed to deserialize JWE message: invalid compact "+
			"JWE: it must have five parts")
	})

	t.Run("pack success but unpack fails with invalid payload auth (iv) data", func(t *testing.T) {
		validAuthPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A192CBCHS384)
		require.NoError(t, err)

		var s []byte

		s, err = validAuthPacker.Pack(cty, origMsg, skidB, recipientsKeys)
		require.NoError(t, err)

		ivStartIndex := bytes.Index(s, []byte("\"iv\""))
		ivEndIndex := ivStartIndex + 6 + bytes.Index(s[ivStartIndex+6:], []byte("\""))
		sTrail := make([]byte, len(s[ivEndIndex:]))
		copy(sTrail, s[ivEndIndex:])
		s = append(s[:ivStartIndex+6], []byte("K3ORqVx392nLcdJveUl_Jg")...) // invalid base64 iv causes decryption error
		s = append(s, sTrail...)

		_, err = validAuthPacker.Unpack(s)
		require.Error(t, err)
		require.Contains(t, err.Error(), "authcrypt Unpack: failed to decrypt JWE envelope: ecdh_factory: "+
			"decryption failed")
	})

	t.Run("pack success but unpack fails with missing keyID in protectedHeader", func(t *testing.T) {
		validAuthPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A192CBCHS384)
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
		kids, _, newRecKeys, _ := createRecipients(t, k, 2)
		validAuthPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A128CBCHS256)
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

	t.Run("pack success but unpack fails with missing kms in packer", func(t *testing.T) {
		kids, _, newRecKeys, _ := createRecipients(t, k, 2)
		validAuthPacker, err := New(newMockProvider(k, cryptoSvc), afgjose.A128CBCHS256)
		require.NoError(t, err)

		ct, err := validAuthPacker.Pack(cty, origMsg, skidB, newRecKeys)
		require.NoError(t, err)

		// rotate keys to update keyID and force a failure
		_, _, err = k.Rotate(kms.NISTP256ECDHKWType, kids[0])
		require.NoError(t, err)

		_, _, err = k.Rotate(kms.NISTP256ECDHKWType, kids[1])
		require.NoError(t, err)

		// mock kms get error
		validAuthPacker.kms = &mockkms.KeyManager{GetKeyErr: errors.New("get error")}

		_, err = validAuthPacker.Unpack(ct)
		require.EqualError(t, err, "authcrypt Unpack: failed to get key from kms: get error")
	})
}

func exportPubKeyBytes(keyHandle *keyset.Handle, kid string) ([]byte, error) {
	pubKH, err := keyHandle.Public()
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, err
	}

	pubKey := &cryptoapi.PublicKey{}

	err = json.Unmarshal(buf.Bytes(), pubKey)
	if err != nil {
		return nil, err
	}

	pubKey.KID = kid

	return json.Marshal(pubKey)
}

// createRecipients and return their public key, jwk kid, didKey and keyset.Handle.
func createRecipients(t *testing.T, k *localkms.LocalKMS,
	recipientsCount int) ([]string, []string, [][]byte, []*keyset.Handle) {
	return createRecipientsByKeyType(t, k, recipientsCount, kms.NISTP256ECDHKW)
}

func createRecipientsByKeyType(t *testing.T, k *localkms.LocalKMS, recipientsCount int,
	kt kms.KeyType) ([]string, []string, [][]byte, []*keyset.Handle) {
	t.Helper()

	var (
		r       [][]byte
		rKH     []*keyset.Handle
		kids    []string
		didKeys []string
	)

	for i := 0; i < recipientsCount; i++ {
		kid, didKey, marshalledPubKey, kh := createAndMarshalKeyByKeyType(t, k, kt)

		r = append(r, marshalledPubKey)
		rKH = append(rKH, kh)
		kids = append(kids, kid)
		didKeys = append(didKeys, didKey)
	}

	return kids, didKeys, r, rKH
}

// createAndMarshalKey creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createAndMarshalKey(t *testing.T, k *localkms.LocalKMS) (string, string, []byte, *keyset.Handle) {
	return createAndMarshalKeyByKeyType(t, k, kms.NISTP256ECDHKWType)
}

func createAndMarshalKeyByKeyType(t *testing.T, k *localkms.LocalKMS,
	kt kms.KeyType) (string, string, []byte, *keyset.Handle) {
	t.Helper()

	kid, keyHandle, err := k.Create(kt)
	require.NoError(t, err)

	kh, ok := keyHandle.(*keyset.Handle)
	require.True(t, ok)

	pubKeyBytes, err := exportPubKeyBytes(kh, kid)
	require.NoError(t, err)

	key := &cryptoapi.PublicKey{}
	err = json.Unmarshal(pubKeyBytes, key)
	require.NoError(t, err)

	// used with marshalled *crypto.PublicKey for encryption keys (it parses 'pubKeyBytes').
	didKey, err := kmsdidkey.BuildDIDKeyByKeyType(pubKeyBytes, kt)
	require.NoError(t, err)

	key.KID = didKey
	mKey, err := json.Marshal(key)
	require.NoError(t, err)

	printKey(t, mKey, kh, kid, didKey)

	return kid, didKey, mKey, kh
}

func printKey(t *testing.T, mPubKey []byte, kh *keyset.Handle, kid, didKey string) {
	t.Helper()

	extractKey, err := extractPrivKey(kh)
	require.NoError(t, err)

	switch keyType := extractKey.(type) {
	case *hybrid.ECPrivateKey:
		t.Logf("** EC key: %s, \n\t kms kid: %s, \n\t jwe kid (did:key):%s", getPrintedECPrivKey(t, keyType), kid,
			didKey)
	case []byte:
		pubKey := new(cryptoapi.PublicKey)
		err := json.Unmarshal(mPubKey, pubKey)
		require.NoError(t, err)

		fullKey := append(keyType, pubKey.X...)
		t.Logf("** X25519 key: %s, \n\t kms kid: %s, \n\t jwe kid (did:key):%s", getPrintedX25519PrivKey(t, fullKey), kid,
			didKey)
	default:
		t.Errorf("not supported key type: %s", keyType)
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

func getPrintedECPrivKey(t *testing.T, privKeyType *hybrid.ECPrivateKey) string {
	jwk := jose.JSONWebKey{
		Key: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: privKeyType.PublicKey.Curve,
				X:     privKeyType.PublicKey.Point.X,
				Y:     privKeyType.PublicKey.Point.Y,
			},
			D: privKeyType.D,
		},
	}

	jwkByte, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return jwkStr
}

func getPrintedX25519PrivKey(t *testing.T, privKeyType ed25519.PrivateKey) string {
	jwk := jose.JSONWebKey{
		Key: privKeyType,
	}

	jwkByte, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return strings.Replace(jwkStr, "Ed25519", "X25519", 1)
}

func extractPrivKey(kh *keyset.Handle) (interface{}, error) {
	nistPECDHKWPrivateKeyTypeURL := "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
	x25519ECDHKWPrivateKeyTypeURL := "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey"
	buf := new(bytes.Buffer)
	w := &privKeyWriter{w: buf}
	nAEAD := &noopAEAD{}

	if kh == nil {
		return nil, fmt.Errorf("extractPrivKey: kh is nil")
	}

	err := kh.Write(w, nAEAD)
	if err != nil {
		return nil, fmt.Errorf("extractPrivKey: retrieving private key failed: %w", err)
	}

	ks := new(tinkpb.Keyset)

	err = proto.Unmarshal(buf.Bytes(), ks)
	if err != nil {
		return nil, errors.New("extractPrivKey: invalid private key")
	}

	primaryKey := ks.Key[0]

	switch primaryKey.KeyData.TypeUrl {
	case nistPECDHKWPrivateKeyTypeURL:
		pbKey := new(ecdhpb.EcdhAeadPrivateKey)

		err = proto.Unmarshal(primaryKey.KeyData.Value, pbKey)
		if err != nil {
			return nil, errors.New("extractPrivKey: invalid key in keyset")
		}

		var c elliptic.Curve

		c, err = hybrid.GetCurve(pbKey.PublicKey.Params.KwParams.CurveType.String())
		if err != nil {
			return nil, fmt.Errorf("extractPrivKey: invalid key: %w", err)
		}

		return hybrid.GetECPrivateKey(c, pbKey.KeyValue), nil
	case x25519ECDHKWPrivateKeyTypeURL:
		pbKey := new(ecdhpb.EcdhAeadPrivateKey)

		err = proto.Unmarshal(primaryKey.KeyData.Value, pbKey)
		if err != nil {
			return nil, errors.New("extractPrivKey: invalid key in keyset")
		}

		if pbKey.PublicKey.Params.KwParams.CurveType.String() != commonpb.EllipticCurveType_CURVE25519.String() {
			return nil, errors.New("extractPrivKey: invalid key curve")
		}

		return pbKey.KeyValue, nil
	}

	return nil, fmt.Errorf("extractPrivKey: can't extract unsupported private key '%s'", primaryKey.KeyData.TypeUrl)
}

type noopAEAD struct{}

func (n noopAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	return plaintext, nil
}

func (n noopAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	return ciphertext, nil
}

type privKeyWriter struct {
	w io.Writer
}

// Write writes the public keyset to the underlying w.Writer. It's not used in this implementation.
func (p *privKeyWriter) Write(_ *tinkpb.Keyset) error {
	return fmt.Errorf("privKeyWriter: write function not supported")
}

// WriteEncrypted writes the encrypted keyset to the underlying w.Writer.
func (p *privKeyWriter) WriteEncrypted(ks *tinkpb.EncryptedKeyset) error {
	return write(p.w, ks)
}

func write(w io.Writer, ks *tinkpb.EncryptedKeyset) error {
	// we write EncryptedKeyset directly without decryption since noopAEAD was used to write *keyset.Handle
	_, e := w.Write(ks.EncryptedKeyset)
	return e
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p, err := mockkms.NewProviderForKMS(mockstorage.NewMockStoreProvider(), &noop.NoLock{})
	require.NoError(t, err)

	k, err := localkms.New("local-lock://test/key/uri", p)
	require.NoError(t, err)

	return k
}

func newMockProvider(customKMS kms.KeyManager,
	customCrypto cryptoapi.Crypto) *mockprovider.Provider {
	return &mockprovider.Provider{
		KMSValue:        customKMS,
		CryptoValue:     customCrypto,
		VDRegistryValue: &mockvdr.MockRegistry{},
	}
}
