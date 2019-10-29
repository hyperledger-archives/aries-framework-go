/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

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

func newWallet(t *testing.T) (*BaseWallet, storage.Store) {
	msp := mockStorage.NewMockStoreProvider()
	p := testProvider{storeProvider: msp}
	store, err := p.StorageProvider().OpenStore("test-wallet")
	require.NoError(t, err)
	ret, err := New(&p)
	require.NoError(t, err)
	return ret, store
}

func TestNewCryptoBox(t *testing.T) {
	w, _ := newWallet(t)
	b, err := NewCryptoBox(w)
	require.NoError(t, err)
	require.Equal(t, b.w, w)

	_, err = NewCryptoBox(Crypto(nil))
	require.EqualError(t, err, "cannot use parameter as wallet")
}

func TestBoxSeal(t *testing.T) {
	var err error

	recipient1Key, err := randCurveKeyPair(rand.Reader)
	require.NoError(t, err)

	w, _ := newWallet(t)
	err = persist(w.keystore, base58.Encode(recipient1Key.EncKeyPair.Pub), recipient1Key)
	require.NoError(t, err)

	b, err := NewCryptoBox(w)
	require.NoError(t, err)

	t.Run("Seal a message with sodiumBoxSeal and unseal it with sodiumBoxSealOpen", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Seal(msg, recipient1Key.EncKeyPair.Pub, rand.Reader)
		require.NoError(t, err)
		dec, err := b.SealOpen(enc, recipient1Key.EncKeyPair.Pub)
		require.NoError(t, err)

		require.Equal(t, msg, dec)
	})

	t.Run("Failed decrypt, key missing from wallet", func(t *testing.T) {
		msg := []byte("pretend this is an encrypted message")

		_, err := b.SealOpen(msg, base58.Decode("BADKEY23452345234523452345"))
		require.NotNil(t, err)
		require.EqualError(t, err, "key not found")
	})

	t.Run("Failed decrypt, short message", func(t *testing.T) {
		enc := []byte("Bad message")

		_, err := b.SealOpen(enc, recipient1Key.EncKeyPair.Pub)
		require.EqualError(t, err, "message too short")
	})

	t.Run("Failed decrypt, garbled message", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Seal(msg, recipient1Key.EncKeyPair.Pub, rand.Reader)
		require.NoError(t, err)

		enc[0]++ // garbling

		_, err = b.SealOpen(enc, recipient1Key.EncKeyPair.Pub)
		require.EqualError(t, err, "failed to unpack")
	})
}

func TestBoxEasy(t *testing.T) {
	var err error

	recipient1Key, err := randCurveKeyPair(rand.Reader)
	require.NoError(t, err)

	w, _ := newWallet(t)
	err = persist(w.keystore, base58.Encode(recipient1Key.EncKeyPair.Pub), recipient1Key)
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

	err = persist(w.keystore, base58.Encode(kp1.Pub), kp1Combo)
	require.NoError(t, err)
	err = persist(w.keystore, base58.Encode(kp2.Pub), kp2Combo)
	require.NoError(t, err)

	b, err := NewCryptoBox(w)
	require.NoError(t, err)

	t.Run("Failed encrypt, key missing from wallet", func(t *testing.T) {
		msg := []byte("pretend this is an encrypted message")

		_, err := b.Easy(msg, nonce, base58.Decode("BADKEY1"), base58.Decode("BADKEY2"))
		require.NotNil(t, err)
		require.EqualError(t, err, "key not found")
	})

	t.Run("Failed decrypt, key missing from wallet", func(t *testing.T) {
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

func randCurveKeyPair(randReader io.Reader) (*cryptoutil.MessagingKeys, error) {
	pk, sk, err := box.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}
	keyPair := cryptoutil.KeyPair{Priv: sk[:], Pub: pk[:]}
	return &cryptoutil.MessagingKeys{
		EncKeyPair: &cryptoutil.EncKeyPair{
			KeyPair: keyPair,
			Alg:     cryptoutil.Curve25519,
		},
	}, nil
}
