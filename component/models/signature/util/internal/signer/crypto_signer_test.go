/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestNewCryptoSigner(t *testing.T) {
	localKMS, err := createKMS()
	require.NoError(t, err)

	tinkCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	tests := []struct {
		keyType      kmsapi.KeyType
		expectedType interface{}
		expectedAlg  string
	}{
		{kmsapi.ED25519Type, ed25519.PublicKey{}, alg},
		{kmsapi.ECDSAP256TypeDER, &ecdsa.PublicKey{}, p256Alg},
		{kmsapi.ECDSAP384TypeDER, &ecdsa.PublicKey{}, p384Alg},
		{kmsapi.ECDSAP521TypeDER, &ecdsa.PublicKey{}, p521Alg},
		{kmsapi.ECDSAP256TypeIEEEP1363, &ecdsa.PublicKey{}, p256Alg},
		{kmsapi.ECDSAP384TypeIEEEP1363, &ecdsa.PublicKey{}, p384Alg},
		{kmsapi.ECDSAP521TypeIEEEP1363, &ecdsa.PublicKey{}, p521Alg},
	}

	for _, test := range tests {
		signer, err := NewCryptoSigner(tinkCrypto, localKMS, test.keyType)
		require.NoError(t, err)
		require.NotNil(t, signer.PubKey)
		require.IsType(t, test.expectedType, signer.PublicKey())
		require.NotEmpty(t, signer.PublicKeyBytes())
		require.NotEmpty(t, signer.KID())

		msg := []byte("test message")
		sigMsg, err := signer.Sign(msg)
		require.NoError(t, err)

		keyHandle, ok := signer.kh.(*keyset.Handle)
		require.True(t, ok)

		publicKeyHandle, err := keyHandle.Public()
		require.NoError(t, err)

		err = tinkCrypto.Verify(sigMsg, msg, publicKeyHandle)
		require.NoError(t, err)

		signerAlg := signer.Alg()
		require.Equal(t, test.expectedAlg, signerAlg)
	}

	t.Run("error corner cases", func(t *testing.T) {
		kms := &mockkms.KeyManager{
			CreateKeyErr: errors.New("key creation error"),
		}
		signer, err := NewCryptoSigner(tinkCrypto, kms, kmsapi.ED25519Type)
		require.Error(t, err)
		require.EqualError(t, err, "key creation error")
		require.Nil(t, signer)

		kms = &mockkms.KeyManager{
			ExportPubKeyBytesErr: errors.New("export public key bytes error"),
		}
		signer, err = NewCryptoSigner(tinkCrypto, kms, kmsapi.ED25519Type)
		require.Error(t, err)
		require.EqualError(t, err, "export public key bytes error")
		require.Nil(t, signer)

		kms = &mockkms.KeyManager{
			ExportPubKeyBytesValue: []byte("not a public key"),
		}
		signer, err = NewCryptoSigner(tinkCrypto, kms, kmsapi.ECDSAP256TypeDER)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse ECDSA public key")
		require.Nil(t, signer)

		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		require.NoError(t, err)
		kms = &mockkms.KeyManager{
			ExportPubKeyBytesValue: pubKeyBytes,
		}
		signer, err = NewCryptoSigner(tinkCrypto, kms, kmsapi.ECDSAP256TypeDER)
		require.Error(t, err)
		require.EqualError(t, err, "unexpected type of ecdsa public key")
		require.Nil(t, signer)

		kms = &mockkms.KeyManager{}
		signer, err = NewCryptoSigner(tinkCrypto, kms, kmsapi.ChaCha20Poly1305Type)
		require.Error(t, err)
		require.EqualError(t, err, "unsupported key type")
		require.Nil(t, signer)
	})
}

func createKMS() (*localkms.LocalKMS, error) {
	p, err := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	if err != nil {
		return nil, err
	}

	return localkms.New("local-lock://custom/master/key/", p)
}
