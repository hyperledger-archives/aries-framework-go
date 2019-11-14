/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockStorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

type testProvider struct {
	storeProvider storage.Provider
}

func (p *testProvider) StorageProvider() storage.Provider {
	return p.storeProvider
}

func (p *testProvider) InboundTransportEndpoint() string {
	return ""
}

func newKMS(t *testing.T) *BaseKMS {
	msp := mockStorage.NewMockStoreProvider()
	p := testProvider{storeProvider: msp}

	ret, err := New(&p)
	require.NoError(t, err)

	return ret
}

func TestNewCryptoBox(t *testing.T) {
	k := newKMS(t)
	b, err := NewCryptoBox(k)
	require.NoError(t, err)
	require.Equal(t, b.km, k)

	_, err = NewCryptoBox(KMS(nil))
	require.EqualError(t, err, "cannot use parameter as KMS")
}

func TestBoxSeal(t *testing.T) {
	var err error

	recipientKeySet, err := randCurveKeySet(rand.Reader)
	require.NoError(t, err)

	recipientPubKey := base58.Decode(recipientKeySet.PrimaryKey.Value)

	k := newKMS(t)

	for _, i := range recipientKeySet.Keys {
		err = persist(k.keystore, i.ID, i)
		require.NoError(t, err)
	}

	err = persist(k.metadatastore, recipientKeySet.ID, recipientKeySet)
	require.NoError(t, err)

	b, err := NewCryptoBox(k)
	require.NoError(t, err)

	t.Run("Seal a message with sodiumBoxSeal and unseal it with sodiumBoxSealOpen", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Seal(msg, recipientPubKey, rand.Reader)
		require.NoError(t, err)
		dec, err := b.SealOpen(enc, recipientPubKey)
		require.NoError(t, err)

		require.Equal(t, msg, dec)
	})

	t.Run("Failed decrypt, key missing from KMS", func(t *testing.T) {
		msg := []byte("pretend this is an encrypted message")

		_, err := b.SealOpen(msg, base58.Decode("BADKEY23452345234523452345"))
		require.NotNil(t, err)
		require.EqualError(t, err, "key not found")
	})

	t.Run("Failed decrypt, short message", func(t *testing.T) {
		enc := []byte("Bad message")

		_, err := b.SealOpen(enc, recipientPubKey)
		require.EqualError(t, err, "message too short")
	})

	t.Run("Failed decrypt, garbled message", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Seal(msg, recipientPubKey, rand.Reader)
		require.NoError(t, err)

		enc[0]++ // garbling

		_, err = b.SealOpen(enc, recipientPubKey)
		require.EqualError(t, err, "failed to unpack")
	})
}

func TestBoxEasy(t *testing.T) {
	var err error

	w := newKMS(t)
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

	pk1Pub := &cryptoutil.Key{
		ID:         hashKeyID(base58.Decode("7cWi6z8efvAHwjNzkdjZe8huoJtqpy6zihsKANJmcAnD"), true, false),
		Value:      "7cWi6z8efvAHwjNzkdjZe8huoJtqpy6zihsKANJmcAnD",
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	err = persist(w.keystore, pk1Pub.ID, pk1Pub)
	require.NoError(t, err)

	pk1Priv := &cryptoutil.Key{
		// in the absence of signature keys, we'll use the public key above as the base keyID
		ID:         hashKeyID(base58.Decode("7cWi6z8efvAHwjNzkdjZe8huoJtqpy6zihsKANJmcAnD"), false, false),
		Value:      "4BsY8pbXj2fjSnAafAvBL2qChnePw5cZML9qjQgAJrUd",
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	err = persist(w.keystore, pk1Priv.ID, pk1Priv)
	require.NoError(t, err)

	kp1KeySet := buildKeySet(pk1Pub, pk1Priv)

	pk2Pub := &cryptoutil.Key{
		ID:         hashKeyID(base58.Decode("7usXitPNvWFEyfH3xNvqxtmn6xwt8jggPVTZ56qxM2G8"), true, false),
		Value:      "7usXitPNvWFEyfH3xNvqxtmn6xwt8jggPVTZ56qxM2G8",
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	err = persist(w.keystore, pk2Pub.ID, pk2Pub)
	require.NoError(t, err)

	pk2Priv := &cryptoutil.Key{
		// in the absence of signature keys, we'll use the public key above as the base keyID
		ID:         hashKeyID(base58.Decode("7usXitPNvWFEyfH3xNvqxtmn6xwt8jggPVTZ56qxM2G8"), false, false),
		Value:      "2U3zcoveWe1BAGem9ije1WwRvDguTPyXCvJRytWcEnS7",
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	err = persist(w.keystore, pk2Priv.ID, pk2Priv)
	require.NoError(t, err)

	kp2KeySet := buildKeySet(pk2Pub, pk2Priv)

	// since StoreProvider is mocked, keystore and metadatastore are the same mocked store in these unit tests.
	// KetSets are stored with full Key values here. See kp1KeySet and kp2KeySet definitions above.
	// Real KMS implementation has only ID values set in SimpleyKey instances of KeySet.
	err = persist(w.metadatastore, kp1KeySet.ID, kp1KeySet)
	require.NoError(t, err)
	err = persist(w.metadatastore, kp2KeySet.ID, kp2KeySet)
	require.NoError(t, err)

	b, err := NewCryptoBox(w)
	require.NoError(t, err)

	t.Run("Failed encrypt, key missing from KMS", func(t *testing.T) {
		msg := []byte("pretend this is an encrypted message")

		_, err := b.Easy(msg, nonce, base58.Decode("BADKEY1"), base58.Decode("BADKEY2"))
		require.NotNil(t, err)
		require.EqualError(t, err, "key not found")
	})

	t.Run("Failed decrypt, key missing from KMS", func(t *testing.T) {
		msg := []byte("pretend this is an encrypted message")

		_, err := b.EasyOpen(msg, nonce, base58.Decode("BADKEY1"), base58.Decode("BADKEY2"))
		require.NotNil(t, err)
		require.EqualError(t, err, "key not found")
	})

	t.Run("Failed decrypt, garbled message", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Easy(msg, nonce, base58.Decode(pk1Pub.Value), base58.Decode(pk2Pub.Value))
		require.NoError(t, err)

		enc[0]++ // garbling

		_, err = b.EasyOpen(enc, nonce, base58.Decode(pk2Pub.Value), base58.Decode(pk1Pub.Value))
		require.EqualError(t, err, "failed to unpack")
	})

	t.Run("success: Easy encrypt and compare against const", func(t *testing.T) {
		nonce := []byte("abcdefghijklmnopqrstuvwx")
		payload := []byte("hjlp! my angry fez vows quit xkcd")

		enc, err := b.Easy(payload, nonce, base58.Decode(pk1Pub.Value), base58.Decode(pk2Pub.Value))
		require.NoError(t, err)

		correct := base58.Decode("GpYpRShjVgLjs9e5mXm85GaQpVqsqmTiaJgsvWCNUsfDQU7fWR89kf6CPfFpPtWGJUR")
		require.ElementsMatch(t, correct, enc)
	})

	t.Run("success: Easy decrypt and compare against const", func(t *testing.T) {
		nonce := []byte("abcdefghijklmnopqrstuvwx")
		payload := base58.Decode("GpYpRShjVgLjs9e5mXm85GaQpVqsqmTiaJgsvWCNUsfDQU7fWR89kf6CPfFpPtWGJUR")

		dec, err := b.EasyOpen(payload, nonce, base58.Decode(pk2Pub.Value), base58.Decode(pk1Pub.Value))
		require.NoError(t, err)

		correct := []byte("hjlp! my angry fez vows quit xkcd")
		require.ElementsMatch(t, correct, dec)
	})
}

func randCurveKeySet(randReader io.Reader) (*cryptoutil.KeySet, error) {
	pk, sk, err := box.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}

	keyPub := &cryptoutil.Key{
		ID:         hashKeyID(pk[:], true, false),
		Value:      base58.Encode(pk[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	keyPriv := &cryptoutil.Key{
		// in the absence of a public signature key, for unit tests only, use the public encryption key (pkB58)
		// as the base key ID for this private encryption key
		ID:         hashKeyID(pk[:], false, false),
		Value:      base58.Encode(sk[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}

	return buildKeySet(keyPub, keyPriv), nil
}

// buildKeySet builds a full fledged KeySet object with key values, not
// just key IDs as in buildKeySetWithIDs(). KetSets must never be stored with full key values.
// Currently used in this file to support mocking KeySets only.
func buildKeySet(keys ...*cryptoutil.Key) *cryptoutil.KeySet {
	keysID := []cryptoutil.Key{}
	for _, k := range keys {
		keysID = append(keysID, *k)
	}
	// build the keySet ID (first key considered the primary key, ie public signing key)
	id := hashKeySetID(base58.Decode(keys[0].Value))

	ks := &cryptoutil.KeySet{
		ID:         id,
		PrimaryKey: *keys[0],
		Keys:       keysID,
	}

	return ks
}
