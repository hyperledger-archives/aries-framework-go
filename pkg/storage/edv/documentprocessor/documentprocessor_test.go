package documentprocessor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
)

const (
	documentID                      = "VJYHHJx4C8J9Fsgz7rZqSp"
	encryptedDocumentContentPayload = "Gemini"
	jweCreatedUsingKeyWeDoNotHave   = `{"protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNT` +
		`ZHQ00iLCJlcGsiOnsidXNlIjoiZW5jIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJCNDYzRVYyd0tfYzFF` +
		`OFJvMk91MVFmNkJvZGZzcXJmbHJjcXdrMVR5YkZjIiwieSI6Ik5rNzhSRjVwSmUxWTF1T0lPVG4ySXJjWHJnYjVoeE` +
		`NKam9RWUotV21KTHMifSwia2lkIjoiIiwidHlwIjoiRURWRW5jcnlwdGVkRG9jdW1lbnQifQ","encrypted_key":` +
		`"ty13RppgkBMLYsOfkq4gvdQwgkDfKZeAy33unLLo_1PhfKa4j1SA-A","iv":"O36okwbi1_ZfVzYG","cipherte` +
		`xt":"d80J0oVrGnrlEgNEjVU_FMDbB03LVFTuHgMOaqQW7bDJgoYwl_wcGBKnduP7YOas5toNLFL7M6VE7wAA5-IVj` +
		`nd5dyLtFtKxBacjNJ0XhhJ6UTSLi3zQG3qIA50fuA","tag":"XgFSOBj96lL3aVP6AhyCmA"}`
)

func TestNew(t *testing.T) {
	createDocumentProcessor(t)
}

func TestAriesDocumentProcessor_Encrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		documentProcessor := createDocumentProcessor(t)

		createEncryptedDocument(t, documentProcessor)
	})
	t.Run("Fail to marshal structured document", func(t *testing.T) {
		documentProcessor := DocumentProcessor{marshal: failingMarshal}
		require.NotNil(t, documentProcessor)

		encryptedDocument, err := documentProcessor.Encrypt(nil)
		require.EqualError(t, err, fmt.Errorf(failMarshalStructuredDocument, errFailingMarshal).Error())
		require.Nil(t, encryptedDocument)
	})
	t.Run("Fail to encrypt structured document", func(t *testing.T) {
		documentProcessor := New(&failingEncrypter{}, nil)
		require.NotNil(t, documentProcessor)

		encryptedDocument, err := documentProcessor.Encrypt(createStructuredDocument())
		require.EqualError(t, err, fmt.Errorf(failEncryptStructuredDocument, errFailingEncrypter).Error())
		require.Nil(t, encryptedDocument)
	})
}

func TestAriesDocumentProcessor_Decrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		documentProcessor := createDocumentProcessor(t)

		encryptedDocument := createEncryptedDocument(t, documentProcessor)

		structuredDocument, err := documentProcessor.Decrypt(encryptedDocument)
		require.NoError(t, err)
		require.Equal(t, structuredDocument.Content["payload"], encryptedDocumentContentPayload)
	})
	t.Run("Fail to deserialize encrypted document's JWE", func(t *testing.T) {
		documentProcessor := createDocumentProcessor(t)

		encryptedDocument := edv.EncryptedDocument{JWE: []byte("Not valid JWE")}

		structuredDocument, err := documentProcessor.Decrypt(&encryptedDocument)
		require.EqualError(t, err,
			fmt.Errorf(failDeserializeJWE, errors.New("invalid compact JWE: it must have five parts")).Error())
		require.Nil(t, structuredDocument)
	})
	t.Run("Fail to decrypt encrypted document - we don't have the key", func(t *testing.T) {
		documentProcessor := createDocumentProcessor(t)

		encryptedDocumentCreatedUsingKeyWeDoNotHave :=
			edv.EncryptedDocument{JWE: []byte(jweCreatedUsingKeyWeDoNotHave)}

		structuredDocument, err := documentProcessor.Decrypt(&encryptedDocumentCreatedUsingKeyWeDoNotHave)
		require.EqualError(t, err,
			fmt.Errorf(failDecryptJWE, errors.New("ecdhes_factory: decryption failed")).Error())
		require.Nil(t, structuredDocument)
	})
}

func createDocumentProcessor(t *testing.T) *DocumentProcessor {
	encrypter, decrypter := createEncrypterAndDecrypter(t)

	documentProcessor := New(encrypter, decrypter)
	require.NotNil(t, documentProcessor)

	return documentProcessor
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

func createStructuredDocument() *edv.StructuredDocument {
	meta := make(map[string]interface{})
	meta["created"] = "2020-10-20"

	content := make(map[string]interface{})
	content["payload"] = encryptedDocumentContentPayload

	structuredDocument := edv.StructuredDocument{
		ID:      documentID,
		Meta:    meta,
		Content: content,
	}

	return &structuredDocument
}

func createEncryptedDocument(t *testing.T, documentProcessor *DocumentProcessor) *edv.EncryptedDocument {
	structuredDocument := createStructuredDocument()

	encryptedDocument, err := documentProcessor.Encrypt(structuredDocument)
	require.NoError(t, err)
	require.NotNil(t, encryptedDocument)

	return encryptedDocument
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
