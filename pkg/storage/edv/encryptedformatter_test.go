package edv

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
)

const (
	testKey                       = "key"
	testValue                     = "data"
	jweCreatedUsingKeyWeDoNotHave = `{"protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNT` +
		`ZHQ00iLCJlcGsiOnsidXNlIjoiZW5jIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJCNDYzRVYyd0tfYzFF` +
		`OFJvMk91MVFmNkJvZGZzcXJmbHJjcXdrMVR5YkZjIiwieSI6Ik5rNzhSRjVwSmUxWTF1T0lPVG4ySXJjWHJnYjVoeE` +
		`NKam9RWUotV21KTHMifSwia2lkIjoiIiwidHlwIjoiRURWRW5jcnlwdGVkRG9jdW1lbnQifQ","encrypted_key":` +
		`"ty13RppgkBMLYsOfkq4gvdQwgkDfKZeAy33unLLo_1PhfKa4j1SA-A","iv":"O36okwbi1_ZfVzYG","cipherte` +
		`xt":"d80J0oVrGnrlEgNEjVU_FMDbB03LVFTuHgMOaqQW7bDJgoYwl_wcGBKnduP7YOas5toNLFL7M6VE7wAA5-IVj` +
		`nd5dyLtFtKxBacjNJ0XhhJ6UTSLi3zQG3qIA50fuA","tag":"XgFSOBj96lL3aVP6AhyCmA"}`
)

var errTest = errors.New("test error")

func TestNewEncryptedFormatter(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		createEncryptedFormatter(t)
	})
	t.Run("Fail to compute MAC for index name", func(t *testing.T) {
		formatter, err := NewEncryptedFormatter(nil, nil,
			NewMACCrypto(nil, &mockcrypto.Crypto{ComputeMACErr: errTest}))
		require.EqualError(t, err, fmt.Errorf(failComputeMACIndexName, errTest).Error())
		require.Nil(t, formatter)
	})
}

func TestEncryptedFormatter_FormatPair(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)

		createEncryptedDocument(t, formatter)
	})
	t.Run("Fail to generate EDV compatible ID", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)

		formatter.randomBytesFunc = failingGenerateRandomBytesFunc

		value, err := formatter.FormatPair(testKey, []byte(testValue))
		require.EqualError(t, err, fmt.Errorf(failGenerateEDVCompatibleID, errGenerateRandomBytes).Error())
		require.Nil(t, value)
	})
	t.Run("Fail to create indexed attribute", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)

		formatter.macCrypto = NewMACCrypto(nil, &mockcrypto.Crypto{ComputeMACErr: errTest})

		value, err := formatter.FormatPair(testKey, []byte(testValue))
		require.EqualError(t, err,
			fmt.Errorf(failCreateIndexedAttribute, fmt.Errorf(failToComputeMACIndexValue, errTest)).Error())
		require.Nil(t, value)
	})
	t.Run("Fail to marshal structured document", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)
		formatter.marshal = failingMarshal

		encryptedDocument, err := formatter.FormatPair(testKey, []byte(testValue))
		require.EqualError(t, err, fmt.Errorf(failMarshalStructuredDocument, errFailingMarshal).Error())
		require.Nil(t, encryptedDocument)
	})
	t.Run("Fail to encrypt structured document", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)
		formatter.jweEncrypter = &failingEncrypter{}

		encryptedDocument, err := formatter.FormatPair(testKey, []byte(testValue))
		require.EqualError(t, err, fmt.Errorf(failEncryptStructuredDocument, errFailingEncrypter).Error())
		require.Nil(t, encryptedDocument)
	})
}

func TestEncryptedFormatter_ParseValue(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)

		encryptedDocumentBytes := createEncryptedDocument(t, formatter)

		value, err := formatter.ParseValue(encryptedDocumentBytes)
		require.NoError(t, err)
		require.Equal(t, string(value), testValue)
	})
	t.Run("Fail to unmarshal encrypted document bytes", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)

		value, err := formatter.ParseValue([]byte("Not a valid encrypted document"))
		require.EqualError(t, err,
			fmt.Errorf(failUnmarshalEncryptedDocument,
				errors.New("invalid character 'N' looking for beginning of value")).Error())
		require.Nil(t, value)
	})
	t.Run("Fail to deserialize encrypted document's JWE", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)

		encryptedDocument := EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		structuredDocument, err := formatter.ParseValue(encryptedDocumentBytes)
		require.EqualError(t, err,
			fmt.Errorf(failDeserializeJWE, errors.New("invalid compact JWE: it must have five parts")).Error())
		require.Nil(t, structuredDocument)
	})
	t.Run("Fail to decrypt encrypted document - we don't have the key", func(t *testing.T) {
		formatter := createEncryptedFormatter(t)

		encryptedDocumentCreatedUsingKeyWeDoNotHave :=
			EncryptedDocument{JWE: []byte(jweCreatedUsingKeyWeDoNotHave)}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocumentCreatedUsingKeyWeDoNotHave)
		require.NoError(t, err)

		structuredDocument, err := formatter.ParseValue(encryptedDocumentBytes)
		require.EqualError(t, err,
			fmt.Errorf(failDecryptJWE, errors.New("ecdhes_factory: decryption failed")).Error())
		require.Nil(t, structuredDocument)
	})
}

func createEncryptedFormatter(t *testing.T) *EncryptedFormatter {
	encrypter, decrypter := createEncrypterAndDecrypter(t)

	formatter, err := NewEncryptedFormatter(encrypter, decrypter, newMACCrypto(t))
	require.NoError(t, err)
	require.NotNil(t, formatter)

	return formatter
}

func createEncrypterAndDecrypter(t *testing.T) (*jose.JWEEncrypt, *jose.JWEDecrypt) {
	keyHandle, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	pubKH, err := keyHandle.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	ecPubKey := new(composite.PublicKey)

	err = json.Unmarshal(buf.Bytes(), ecPubKey)
	require.NoError(t, err)

	encrypter, err := jose.NewJWEEncrypt(jose.A256GCM, "EDVEncryptedDocument", "", nil,
		[]*composite.PublicKey{ecPubKey})
	require.NoError(t, err)

	decrypter := jose.NewJWEDecrypt(nil, keyHandle)

	return encrypter, decrypter
}

func newMACCrypto(t *testing.T) *MACCrypto {
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	require.NoError(t, err)
	require.NotNil(t, kh)

	crypto, err := tinkcrypto.New()
	require.NoError(t, err)

	return NewMACCrypto(kh, crypto)
}

func createEncryptedDocument(t *testing.T, formatter *EncryptedFormatter) []byte {
	encryptedDocumentBytes, err := formatter.FormatPair(testKey, []byte(testValue))
	require.NoError(t, err)
	require.NotNil(t, encryptedDocumentBytes)

	return encryptedDocumentBytes
}

var errFailingMarshal = errors.New("failingMarshal always fails")

func failingMarshal(interface{}) ([]byte, error) {
	return nil, errFailingMarshal
}

type failingEncrypter struct {
}

var errFailingEncrypter = errors.New("failingEncrypter always fails")

func (f *failingEncrypter) EncryptWithAuthData([]byte, []byte) (*jose.JSONWebEncryption, error) {
	panic("implement me")
}

func (f *failingEncrypter) Encrypt([]byte) (*jose.JSONWebEncryption, error) {
	return nil, errFailingEncrypter
}

var errGenerateRandomBytes = errors.New("failingGenerateRandomBytesFunc always fails")

func failingGenerateRandomBytesFunc([]byte) (int, error) {
	return -1, errGenerateRandomBytes
}
