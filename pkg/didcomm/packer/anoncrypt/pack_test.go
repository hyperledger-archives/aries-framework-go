/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anoncrypt

import (
	"encoding/json"
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
)

func TestAnoncryptPackerSuccess(t *testing.T) {
	k := createKMS(t)
	_, recipientsKeys, keyHandles := createRecipients(t, k, 10)

	anonPacker := New(newMockProviderWithCustomKMS(k), jose.A256GCM)

	origMsg := []byte("secret message")
	ct, err := anonPacker.Pack(origMsg, nil, recipientsKeys)
	require.NoError(t, err)

	msg, err := anonPacker.Unpack(ct)
	require.NoError(t, err)

	recKey, err := exportPubKeyBytes(keyHandles[0])
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{Message: origMsg, ToVerKey: recKey}, msg)

	// try with only 1 recipient
	ct, err = anonPacker.Pack(origMsg, nil, [][]byte{recipientsKeys[0]})
	require.NoError(t, err)

	msg, err = anonPacker.Unpack(ct)
	require.NoError(t, err)

	require.EqualValues(t, &transport.Envelope{Message: origMsg, ToVerKey: recKey}, msg)

	require.Equal(t, encodingType, anonPacker.EncodingType())
}

func TestAnoncryptPackerFail(t *testing.T) {
	k := createKMS(t)
	_, recipientsKeys, _ := createRecipients(t, k, 10)
	origMsg := []byte("secret message")
	anonPacker := New(newMockProviderWithCustomKMS(k), jose.A256GCM)

	t.Run("pack fail with empty recipients keys", func(t *testing.T) {
		_, err := anonPacker.Pack(origMsg, nil, nil)
		require.EqualError(t, err, "anoncrypt Pack: empty recipientsPubKeys")
	})

	t.Run("pack fail with invalid recipients keys", func(t *testing.T) {
		_, err := anonPacker.Pack(origMsg, nil, [][]byte{[]byte("invalid")})
		require.EqualError(t, err, "anoncrypt Pack: failed to convert recipient keys: invalid character 'i' "+
			"looking for beginning of value")
	})

	t.Run("pack fail with invalid encAlg", func(t *testing.T) {
		invalidAlg := "invalidAlg"
		invalidAnonPacker := New(newMockProviderWithCustomKMS(k), jose.EncAlg(invalidAlg))
		_, err := invalidAnonPacker.Pack(origMsg, nil, recipientsKeys)
		require.EqualError(t, err, fmt.Sprintf("anoncrypt Pack: failed to new JWEEncrypt instance: encryption"+
			" algorithm '%s' not supported", invalidAlg))
	})

	t.Run("pack success but unpack fails with invalid payload", func(t *testing.T) {
		validAnonPacker := New(newMockProviderWithCustomKMS(k), jose.A256GCM)
		_, err := validAnonPacker.Pack(origMsg, nil, recipientsKeys)
		require.NoError(t, err)

		_, err = validAnonPacker.Unpack([]byte("invalid jwe envelope"))
		require.EqualError(t, err, "anoncrypt Unpack: failed to deserialize JWE message: invalid compact "+
			"JWE: it must have five parts")
	})

	t.Run("pack success but unpack fails with missing keyID in protectedHeader", func(t *testing.T) {
		validAnonPacker := New(newMockProviderWithCustomKMS(k), jose.A256GCM)
		ct, err := validAnonPacker.Pack(origMsg, nil, [][]byte{recipientsKeys[0]})
		require.NoError(t, err)

		jwe, err := jose.Deserialize(string(ct))
		require.NoError(t, err)

		delete(jwe.ProtectedHeaders, jose.HeaderKeyID)

		newCT, err := jwe.CompactSerialize(json.Marshal)
		require.NoError(t, err)

		_, err = validAnonPacker.Unpack([]byte(newCT))
		require.EqualError(t, err, "anoncrypt Unpack: single recipient missing 'KID' in jwe.ProtectHeaders")
	})

	t.Run("pack success but unpack fails with missing kid in kms", func(t *testing.T) {
		kids, newRecKeys, _ := createRecipients(t, k, 2)
		validAnonPacker := New(newMockProviderWithCustomKMS(k), jose.A256GCM)
		ct, err := validAnonPacker.Pack(origMsg, nil, newRecKeys)
		require.NoError(t, err)

		// rotate keys to update keyID and force a failure
		_, _, err = k.Rotate(kms.ECDHES256AES256GCMType, kids[0])
		require.NoError(t, err)

		_, _, err = k.Rotate(kms.ECDHES256AES256GCMType, kids[1])
		require.NoError(t, err)

		_, err = validAnonPacker.Unpack(ct)
		require.EqualError(t, err, "anoncrypt Unpack: no matching recipient in envelope")
	})
}

// createRecipients and return their public key and keyset.Handle
func createRecipients(t *testing.T, k *localkms.LocalKMS, recipientsCount int) ([]string, [][]byte, []*keyset.Handle) {
	t.Helper()

	var (
		r    [][]byte
		rKH  []*keyset.Handle
		kids []string
	)

	for i := 0; i < recipientsCount; i++ {
		kid, marshalledPubKey, kh := createAndMarshalRecipient(t, k)

		r = append(r, marshalledPubKey)
		rKH = append(rKH, kh)
		kids = append(kids, kid)
	}

	return kids, r, rKH
}

// createAndMarshalRecipient creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle
func createAndMarshalRecipient(t *testing.T, k *localkms.LocalKMS) (string, []byte, *keyset.Handle) {
	t.Helper()

	kid, keyHandle, err := k.Create(kms.ECDHES256AES256GCMType)
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

func newMockProviderWithCustomKMS(customKMS kms.KeyManager) *mockprovider.Provider {
	return &mockprovider.Provider{
		KMSValue: customKMS,
	}
}
