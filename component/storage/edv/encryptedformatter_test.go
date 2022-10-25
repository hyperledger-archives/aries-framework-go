/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package edv_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/formattedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func TestEncryptedFormatterInFormatProvider(t *testing.T) {
	t.Run("With random document IDs", func(t *testing.T) {
		t.Run("Without cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), createValidEncryptedFormatter(t))
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
		t.Run("With cache", func(t *testing.T) {
			provider := cachedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(), createValidEncryptedFormatter(t)), mem.NewProvider())
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
	})
	t.Run("With deterministic document IDs", func(t *testing.T) {
		t.Run("Without cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(),
				createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()))
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
		t.Run("With cache", func(t *testing.T) {
			provider := cachedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(),
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs())),
				mem.NewProvider())
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
	})
}

func TestEncryptedFormatter_Deformat(t *testing.T) {
	t.Run("Attempt to deformat a nil formatted value", func(t *testing.T) {
		encryptedFormatter := createValidEncryptedFormatter(t)

		_, _, _, err := encryptedFormatter.Deformat("", nil)
		require.EqualError(t, err, "EDV encrypted formatter requires the formatted value in order to "+
			"return the deformatted key and tags")
	})
	t.Run("Fail to unmarshal encrypted document bytes", func(t *testing.T) {
		encryptedFormatter := createValidEncryptedFormatter(t)

		_, _, _, err := encryptedFormatter.Deformat("", []byte("This isn't a valid marshalled encrypted document"))
		require.EqualError(t, err, "failed to get structured document from encrypted document bytes: "+
			"failed to unmarshal value into an encrypted document: invalid character 'T' looking for beginning of value")
	})
	t.Run("Fail to deserialize JWE", func(t *testing.T) {
		encryptedFormatter := createValidEncryptedFormatter(t)

		_, _, _, err := encryptedFormatter.Deformat("", []byte(`{"jwe":"NotValidJWE"}`))
		require.EqualError(t, err, "failed to get structured document from encrypted document bytes: "+
			"failed to deserialize JWE: invalid compact JWE: it must have five parts")
	})
}

func createValidEncryptedFormatter(t *testing.T, options ...edv.EncryptedFormatterOption) *edv.EncryptedFormatter {
	kmsSvc, cryptoSvc := createKMSAndCrypto(t)
	encrypter, decrypter, _ := createEncrypterAndDecrypter(t, kmsSvc, cryptoSvc)

	formatter := edv.NewEncryptedFormatter(encrypter, decrypter, createValidMACCrypto(t),
		options...)
	require.NotNil(t, formatter)

	return formatter
}

func createKMSAndCrypto(t *testing.T) (kms.KeyManager, cryptoapi.Crypto) {
	p, err := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	require.NoError(t, err)

	kmsSvc, err := localkms.New("local-lock://test/master/key/", p)
	require.NoError(t, err)

	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	return kmsSvc, cryptoSvc
}

func createEncrypterAndDecrypter(t *testing.T, kmsSvc kms.KeyManager,
	cryptoSvc cryptoapi.Crypto) (*jose.JWEEncrypt, *jose.JWEDecrypt, string) {
	kid, ecPubKeyBytes, err := kmsSvc.CreateAndExportPubKeyBytes(kms.NISTP256ECDHKWType)
	require.NoError(t, err)

	ecPubKey := new(cryptoapi.PublicKey)

	err = json.Unmarshal(ecPubKeyBytes, ecPubKey)
	require.NoError(t, err)

	encrypter, err := jose.NewJWEEncrypt(jose.A256GCM, "application/JSON",
		"", "", nil, []*cryptoapi.PublicKey{ecPubKey}, cryptoSvc)
	require.NoError(t, err)

	decrypter := jose.NewJWEDecrypt(nil, cryptoSvc, kmsSvc)

	return encrypter, decrypter, kid
}
