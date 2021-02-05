/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package edv_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/component/storageutil/formattedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func TestEncryptedFormatterInFormatProvider(t *testing.T) {
	t.Run("With EDV Encrypted Formatter", func(t *testing.T) {
		t.Run("Without cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), createValidEncryptedFormatter(t))
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider)
		})
		t.Run("With cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), createValidEncryptedFormatter(t),
				formattedstore.WithCacheProvider(mem.NewProvider()))
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider)
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

func createValidEncryptedFormatter(t *testing.T) *edv.EncryptedFormatter {
	encrypter, decrypter := createEncrypterAndDecrypter(t)

	formatter := edv.NewEncryptedFormatter(encrypter, decrypter, createValidMACCrypto(t))
	require.NotNil(t, formatter)

	return formatter
}

func createEncrypterAndDecrypter(t *testing.T) (*jose.JWEEncrypt, *jose.JWEDecrypt) {
	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	keyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	kmsSvc := &mockkms.KeyManager{
		GetKeyValue: keyHandle,
	}

	pubKH, err := keyHandle.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	ecPubKey := new(cryptoapi.PublicKey)

	err = json.Unmarshal(buf.Bytes(), ecPubKey)
	require.NoError(t, err)

	encrypter, err := jose.NewJWEEncrypt(jose.A256GCM, "EDVEncryptedDocument", "", nil,
		[]*cryptoapi.PublicKey{ecPubKey}, cryptoSvc)
	require.NoError(t, err)

	decrypter := jose.NewJWEDecrypt(nil, cryptoSvc, kmsSvc)

	return encrypter, decrypter
}
