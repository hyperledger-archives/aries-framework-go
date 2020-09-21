/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/wrapper/prefix"
)

func TestAuthryptPackerSuccess(t *testing.T) {
	k := createKMS(t)
	_, recipientsKeys, keyHandles := createRecipients(t, k, 10)

	skid, senderKey, _ := createAndMarshalKey(t, k)

	thirdPartyKeyStore := make(map[string][]byte)
	mockStoreProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: thirdPartyKeyStore,
	}}

	authPacker, err := New(newMockProvider(mockStoreProvider, k), jose.A256GCM)
	require.NoError(t, err)

	// add sender key in thirdPartyKS (prep step before Authcrypt.Pack()/Unpack())
	fromWrappedKID := prefix.StorageKIDPrefix + skid
	thirdPartyKeyStore[fromWrappedKID] = senderKey

	origMsg := []byte("secret message")
	ct, err := authPacker.Pack(origMsg, []byte(skid), recipientsKeys)
	require.NoError(t, err)

	msg, err := authPacker.Unpack(ct)
	require.NoError(t, err)

	recKey, err := exportPubKeyBytes(keyHandles[0])
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{Message: origMsg, ToKey: recKey}, msg)

	// try with only 1 recipient
	ct, err = authPacker.Pack(origMsg, []byte(skid), [][]byte{recipientsKeys[0]})
	require.NoError(t, err)

	msg, err = authPacker.Unpack(ct)
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{Message: origMsg, ToKey: recKey}, msg)

	require.Equal(t, encodingType, authPacker.EncodingType())
}

func TestAuthcryptPackerFail(t *testing.T) {
	k := createKMS(t)

	skid, senderKey, _ := createAndMarshalKey(t, k)

	t.Run("new Pack fail with nil thirdPartyKS provider", func(t *testing.T) {
		_, err := New(newMockProvider(nil, k), jose.A256GCM)
		require.EqualError(t, err, "authcrypt: failed to create packer because StorageProvider is empty")
	})

	t.Run("new Pack fail with bad thirdPartyKS provider", func(t *testing.T) {
		badStoreProvider := &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("failed to open thirdPartyKS"),
			FailNamespace:      ThirdPartyKeysDB,
		}

		_, err := New(newMockProvider(badStoreProvider, k), jose.A256GCM)
		require.EqualError(t, err, "authcrypt: failed to open store for name space thirdpartykeysdb")
	})

	mockStoreMap := make(map[string][]byte)
	mockStoreProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: mockStoreMap,
	}}

	t.Run("new Pack fail with nil kms", func(t *testing.T) {
		_, err := New(newMockProvider(mockStoreProvider, nil), jose.A256GCM)
		require.EqualError(t, err, "authcrypt: failed to create packer because KMS is empty")
	})

	_, recipientsKeys, _ := createRecipients(t, k, 10)
	origMsg := []byte("secret message")
	authPacker, err := New(newMockProvider(mockStoreProvider, k), jose.A256GCM)
	require.NoError(t, err)

	mockStoreMap[skid] = senderKey
	skidB := []byte(skid)

	t.Run("pack fail with empty recipients keys", func(t *testing.T) {
		_, err := authPacker.Pack(origMsg, nil, nil)
		require.EqualError(t, err, "authcrypt Pack: empty recipientsPubKeys")
	})

	t.Run("pack fail with invalid recipients keys", func(t *testing.T) {
		_, err := authPacker.Pack(origMsg, nil, [][]byte{[]byte("invalid")})
		require.EqualError(t, err, "authcrypt Pack: failed to convert recipient keys: invalid character 'i' "+
			"looking for beginning of value")
	})

	t.Run("pack fail with invalid encAlg", func(t *testing.T) {
		invalidAlg := "invalidAlg"
		invalidAuthPacker, err := New(newMockProvider(mockStoreProvider, k), jose.EncAlg(invalidAlg))
		require.NoError(t, err)

		_, err = invalidAuthPacker.Pack(origMsg, skidB, recipientsKeys)
		require.EqualError(t, err, fmt.Sprintf("authcrypt Pack: failed to new JWEEncrypt instance: encryption"+
			" algorithm '%s' not supported", invalidAlg))
	})

	t.Run("pack fail with KMS can't get sender key", func(t *testing.T) {
		badKMSStoreProvider := mockstorage.NewCustomMockStoreProvider(
			&mockstorage.MockStore{ErrGet: errors.New("bad fake key ID")})
		p := mockkms.NewProviderForKMS(badKMSStoreProvider, &noop.NoLock{})

		badKMS, err := localkms.New("local-lock://test/key/uri", p)
		require.NoError(t, err)

		badAuthPacker, err := New(newMockProvider(mockStoreProvider, badKMS), jose.A256GCM)
		require.NoError(t, err)

		_, err = badAuthPacker.Pack(origMsg, skidB, recipientsKeys)
		require.Contains(t, fmt.Sprintf("%v", err), "bad fake key ID")
	})

	t.Run("pack success but unpack fails with invalid payload", func(t *testing.T) {
		validAuthPacker, err := New(newMockProvider(mockStoreProvider, k), jose.A256GCM)
		require.NoError(t, err)

		_, err = validAuthPacker.Pack(origMsg, skidB, recipientsKeys)
		require.NoError(t, err)

		_, err = validAuthPacker.Unpack([]byte("invalid jwe envelope"))
		require.EqualError(t, err, "authcrypt Unpack: failed to deserialize JWE message: invalid compact "+
			"JWE: it must have five parts")
	})

	t.Run("pack success but unpack fails with missing keyID in protectedHeader", func(t *testing.T) {
		validAuthPacker, err := New(newMockProvider(mockStoreProvider, k), jose.A256GCM)
		require.NoError(t, err)

		ct, err := validAuthPacker.Pack(origMsg, skidB, [][]byte{recipientsKeys[0]})
		require.NoError(t, err)

		jwe, err := jose.Deserialize(string(ct))
		require.NoError(t, err)

		delete(jwe.ProtectedHeaders, jose.HeaderKeyID)

		newCT, err := jwe.CompactSerialize(json.Marshal)
		require.NoError(t, err)

		_, err = validAuthPacker.Unpack([]byte(newCT))
		require.EqualError(t, err, "authcrypt Unpack: single recipient missing 'KID' in jwe.ProtectHeaders")
	})

	t.Run("pack success but unpack fails with missing kid in kms", func(t *testing.T) {
		kids, newRecKeys, _ := createRecipients(t, k, 2)
		validAuthPacker, err := New(newMockProvider(mockStoreProvider, k), jose.A256GCM)
		require.NoError(t, err)

		ct, err := validAuthPacker.Pack(origMsg, skidB, newRecKeys)
		require.NoError(t, err)

		// rotate keys to update keyID and force a failure
		_, _, err = k.Rotate(kms.ECDH1PU256AES256GCMType, kids[0])
		require.NoError(t, err)

		_, _, err = k.Rotate(kms.ECDH1PU256AES256GCMType, kids[1])
		require.NoError(t, err)

		_, err = validAuthPacker.Unpack(ct)
		require.EqualError(t, err, "authcrypt Unpack: no matching recipient in envelope")
	})
}

// createRecipients and return their public key and keyset.Handle.
func createRecipients(t *testing.T, k *localkms.LocalKMS, recipientsCount int) ([]string, [][]byte, []*keyset.Handle) {
	t.Helper()

	var (
		r    [][]byte
		rKH  []*keyset.Handle
		kids []string
	)

	for i := 0; i < recipientsCount; i++ {
		kid, marshalledPubKey, kh := createAndMarshalKey(t, k)

		r = append(r, marshalledPubKey)
		rKH = append(rKH, kh)
		kids = append(kids, kid)
	}

	return kids, r, rKH
}

// createAndMarshalKey creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createAndMarshalKey(t *testing.T, k *localkms.LocalKMS) (string, []byte, *keyset.Handle) {
	t.Helper()

	kid, keyHandle, err := k.Create(kms.ECDH1PU256AES256GCMType)
	require.NoError(t, err)

	kh, ok := keyHandle.(*keyset.Handle)
	require.True(t, ok)

	pubKeyBytes, err := exportPubKeyBytes(kh)
	require.NoError(t, err)

	key := &composite.PublicKey{}
	err = json.Unmarshal(pubKeyBytes, key)
	require.NoError(t, err)

	key.KID = kid
	mKey, err := json.Marshal(key)
	require.NoError(t, err)

	return kid, mKey, kh
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p := mockkms.NewProviderForKMS(mockstorage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://test/key/uri", p)
	require.NoError(t, err)

	return k
}

func newMockProvider(customStoreProvider storage.Provider, customKMS kms.KeyManager) *mockprovider.Provider {
	return &mockprovider.Provider{
		KMSValue:             customKMS,
		StorageProviderValue: customStoreProvider,
	}
}
