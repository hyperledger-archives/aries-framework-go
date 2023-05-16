/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
)

type testProvider struct {
	storeProvider      kms.Store
	secretLockProvider secretlock.Service
}

func (p *testProvider) StorageProvider() kms.Store {
	return p.storeProvider
}

func (p *testProvider) SecretLock() secretlock.Service {
	return p.secretLockProvider
}

func newKMS(t *testing.T) *LocalKMS {
	testStore := newInMemoryKMSStore()
	p := testProvider{
		storeProvider:      testStore,
		secretLockProvider: &noop.NoLock{},
	}

	mainLockURI := "local-lock://test/uri/"
	ret, err := New(mainLockURI, &p)
	require.NoError(t, err)

	return ret
}

func TestNewCryptoBox(t *testing.T) {
	k := newKMS(t)
	b, err := NewCryptoBox(k)
	require.NoError(t, err)
	require.Equal(t, b.km, k)

	_, err = NewCryptoBox(kms.KeyManager(nil))
	require.EqualError(t, err, "cannot use parameter argument as KMS")
}

func TestBoxSeal(t *testing.T) {
	k := newKMS(t)
	_, rec1PubKey, err := k.CreateAndExportPubKeyBytes(kms.ED25519)
	require.NoError(t, err)

	rec1EncPubKey, err := cryptoutil.PublicEd25519toCurve25519(rec1PubKey)
	require.NoError(t, err)

	b, err := NewCryptoBox(k)
	require.NoError(t, err)

	t.Run("Seal a message with sodiumBoxSeal and unseal it with sodiumBoxSealOpen", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Seal(msg, rec1EncPubKey, rand.Reader)
		require.NoError(t, err)
		dec, err := b.SealOpen(enc, rec1PubKey)
		require.NoError(t, err)

		require.Equal(t, msg, dec)
	})

	t.Run("Failed decrypt, key missing from KMS", func(t *testing.T) {
		msg := []byte("pretend this is an encrypted message")

		_, err := b.SealOpen(msg, base58.Decode("BADKEY23452345234523452345"))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "sealOpen: failed to exportPriveKeyBytes: getKeySet: "+
			"failed to read json keyset from reader")
	})

	t.Run("Failed decrypt, short message", func(t *testing.T) {
		enc := []byte("Bad message")

		_, err := b.SealOpen(enc, rec1PubKey)
		require.EqualError(t, err, "message too short")
	})

	t.Run("Failed decrypt, garbled message", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Seal(msg, rec1EncPubKey, rand.Reader)
		require.NoError(t, err)

		enc[0]++ // garbling

		_, err = b.SealOpen(enc, rec1PubKey)
		require.EqualError(t, err, "failed to unpack")
	})
}

/* Cannot convert X25519 keys to ED25519 keys, this test assumes fixed X25519 keys values. The KMS cannot store
	encryption X25519 keys. The new KMS supports storing only ED25519 keys. For the sake of LegacyPacker,
    Crypto_Box.go converts from Ed25519 to X25519 only.

func TestBoxEasy(t *testing.T) {
	k, _ := newKMS(t)
	recipient1KID, _, err := k.Create(kms.ED25519)
	require.NoError(t, err)

	rec1PubKey, err := k.ExportPubKeyBytes(recipient1KID)
	require.NoError(t, err)

	rec1EncPubKey, err := cryptoutil.PublicEd25519toCurve25519(rec1PubKey)
	require.NoError(t, err)

	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

	kp1 := cryptoutil.KeyPair{
		Priv: base58.Decode("4BsY8pbXj2fjSnAafAvBL2qChnePw5cZML9qjQgAJrUd"),
		Pub:  base58.Decode("7cWi6z8efvAHwjNzkdjZe8huoJtqpy6zihsKANJmcAnD"),
	}
	kp1Combo := &cryptoutil.MessagingKeys{
		EncKeyPair: &cryptoutil.EncKeyPair{
			KeyPair: kp1,
			Alg:     cryptoutil.Curve25519,
		},
	}
	kp2 := cryptoutil.KeyPair{
		Priv: base58.Decode("2U3zcoveWe1BAGem9ije1WwRvDguTPyXCvJRytWcEnS7"),
		Pub:  base58.Decode("7usXitPNvWFEyfH3xNvqxtmn6xwt8jggPVTZ56qxM2G8"),
	}
	kp2Combo := &cryptoutil.MessagingKeys{
		EncKeyPair: &cryptoutil.EncKeyPair{
			KeyPair: kp2,
			Alg:     cryptoutil.Curve25519,
		},
	}

	err = kms.persist(w.keystore, base58.Encode(kp1.Pub), kp1Combo)
	require.NoError(t, err)
	err = kms.persist(w.keystore, base58.Encode(kp2.Pub), kp2Combo)
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

		enc, err := b.Easy(msg, nonce, kp1.Pub, kp2.Pub)
		require.NoError(t, err)

		enc[0]++ // garbling

		_, err = b.EasyOpen(enc, nonce, kp2.Pub, kp1.Pub)
		require.EqualError(t, err, "failed to unpack")
	})

	t.Run("success: Easy encrypt and compare against const", func(t *testing.T) {
		nonce := []byte("abcdefghijklmnopqrstuvwx")
		payload := []byte("hjlp! my angry fez vows quit xkcd")

		enc, err := b.Easy(payload, nonce, kp1.Pub, kp2.Pub)
		require.NoError(t, err)

		correct := base58.Decode("GpYpRShjVgLjs9e5mXm85GaQpVqsqmTiaJgsvWCNUsfDQU7fWR89kf6CPfFpPtWGJUR")
		require.ElementsMatch(t, correct, enc)
	})

	t.Run("success: Easy decrypt and compare against const", func(t *testing.T) {
		nonce := []byte("abcdefghijklmnopqrstuvwx")
		payload := base58.Decode("GpYpRShjVgLjs9e5mXm85GaQpVqsqmTiaJgsvWCNUsfDQU7fWR89kf6CPfFpPtWGJUR")

		dec, err := b.EasyOpen(payload, nonce, kp2.Pub, kp1.Pub)
		require.NoError(t, err)

		correct := []byte("hjlp! my angry fez vows quit xkcd")
		require.ElementsMatch(t, correct, dec)
	})
}
*/
