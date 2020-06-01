/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature/internal/signer"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

func TestNewCryptoSigner(t *testing.T) {
	p := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	localKMS, err := localkms.New("local-lock://custom/master/key/", p)
	require.NoError(t, err)

	tinkCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	for _, keyType := range [...]kmsapi.KeyType{
		kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP521TypeDER,
		kmsapi.ECDSAP256TypeIEEEP1363, kmsapi.ECDSAP521TypeIEEEP1363, kmsapi.ED25519Type,
		kmsapi.ECDSAP384TypeIEEEP1363, kmsapi.ECDSASecp256k1TypeIEEEP1363, kmsapi.RSARS256Type, kmsapi.RSAPS256Type,
	} {
		newSigner, signerErr := NewCryptoSigner(tinkCrypto, localKMS, keyType)
		require.NoError(t, signerErr)

		msgSig, signerErr := newSigner.Sign([]byte("test message"))
		require.NoError(t, signerErr)
		require.NotEmpty(t, msgSig)
	}

	newSigner, err := NewCryptoSigner(tinkCrypto, localKMS, kmsapi.ChaCha20Poly1305Type)
	require.Error(t, err)
	require.EqualError(t, err, "unsupported key type")
	require.Nil(t, newSigner)
}

func TestNewSigner(t *testing.T) {
	for _, keyType := range [...]kmsapi.KeyType{
		kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP521TypeDER,
		kmsapi.ECDSAP256TypeIEEEP1363, kmsapi.ECDSAP521TypeIEEEP1363, kmsapi.ED25519Type,
		kmsapi.ECDSAP384TypeIEEEP1363, kmsapi.ECDSASecp256k1TypeIEEEP1363, kmsapi.RSARS256Type, kmsapi.RSAPS256Type,
	} {
		newSigner, signerErr := NewSigner(keyType)
		require.NoError(t, signerErr)

		msgSig, signerErr := newSigner.Sign([]byte("test message"))
		require.NoError(t, signerErr)
		require.NotEmpty(t, msgSig)
	}

	invalidSigner, err := NewSigner(kmsapi.ChaCha20Poly1305Type)
	require.Error(t, err)
	require.EqualError(t, err, "unsupported key type")
	require.Nil(t, invalidSigner)
}

func TestGetEd25519Signer(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ed25519Signer := GetEd25519Signer(privKey, pubKey)
	require.NotNil(t, ed25519Signer)
	require.IsType(t, &signer.Ed25519Signer{}, ed25519Signer)
}
