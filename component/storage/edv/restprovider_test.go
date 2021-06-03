/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

const testServerURL = "http://localhost:8071/encrypted-data-vaults"

var logger = log.New("EDV-Provider-Test")

type failingEncrypter struct{}

func (f *failingEncrypter) EncryptWithAuthData([]byte, []byte) (*jose.JSONWebEncryption, error) {
	panic("implement me")
}

func (f *failingEncrypter) Encrypt([]byte) (*jose.JSONWebEncryption, error) {
	return nil, errors.New("failingEncrypter always fails")
}

type failingDecrypter struct{}

func (m *failingDecrypter) Decrypt(*jose.JSONWebEncryption) ([]byte, error) {
	return nil, errors.New("failingDecrypter always fails")
}

func TestCommon(t *testing.T) {
	t.Run("With random document IDs", func(t *testing.T) {
		t.Run("Without batch endpoint extension", func(t *testing.T) {
			t.Run(`Without "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t, createValidEncryptedFormatter(t))
				runCommonTests(t, edvRESTProvider)
			})
			t.Run(`With "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t, createValidEncryptedFormatter(t),
					edv.WithFullDocumentsReturnedFromQueries())
				runCommonTests(t, edvRESTProvider)
			})
		})
		t.Run("With batch endpoint extension", func(t *testing.T) {
			t.Run(`Without "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t, createValidEncryptedFormatter(t),
					edv.WithBatchEndpointExtension())
				runCommonTests(t, edvRESTProvider)
			})
			t.Run(`With "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t, createValidEncryptedFormatter(t),
					edv.WithBatchEndpointExtension(),
					edv.WithFullDocumentsReturnedFromQueries())
				runCommonTests(t, edvRESTProvider)
			})
		})
	})
	t.Run("With deterministic document IDs", func(t *testing.T) {
		t.Run("Without batch endpoint extension", func(t *testing.T) {
			t.Run(`Without "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t,
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()))
				runCommonTests(t, edvRESTProvider)
			})
			t.Run(`With "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t,
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()),
					edv.WithFullDocumentsReturnedFromQueries())
				runCommonTests(t, edvRESTProvider)
			})
		})
		t.Run("With batch endpoint extension", func(t *testing.T) {
			t.Run(`Without "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t,
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()),
					edv.WithBatchEndpointExtension())
				runCommonTests(t, edvRESTProvider)
			})
			t.Run(`With "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t,
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()),
					edv.WithBatchEndpointExtension(),
					edv.WithFullDocumentsReturnedFromQueries())
				runCommonTests(t, edvRESTProvider)
			})
		})
	})
}

func TestRESTStore_Put(t *testing.T) {
	t.Run("Fail to generate encrypted document ID and encrypted document bytes "+
		"for vault operation (batch extension enabled)", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter, edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("Key", []byte("Value"))
		require.EqualError(t, err, "failed to store data using a deterministic document ID: "+
			"failed to store document using deterministic ID and batch endpoint: "+
			"failed to generate the encrypted document ID and encrypted document bytes: "+
			`failed to format key into an encrypted document ID: failed to compute MAC based on key "Key": `+
			"bad key handle format")
	})
	t.Run("Fail to put data in EDV server (batch extension enabled)", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()), edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("Key", []byte("Value"))
		require.EqualError(t, err, `failed to store data using a deterministic document ID: `+
			`failed to store document using deterministic ID and batch endpoint: `+
			`failed to put data in EDV server via the batch endpoint `+
			`(is it enabled in the EDV server?): failed to send POST request: failed to send request: `+
			`Post "InvalidURL/InvalidVaultID/batch": unsupported protocol scheme ""`)
	})
	t.Run("Fail to reach read document endpoint (using standard endpoints)", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("Key", []byte("Value"))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed to store data using a deterministic document ID: "+
			"failed to store document using random document ID and standard endpoints: "+
			"failed to create or update document based on document ID: "+
			`failed to determine if an EDV document for key "Key" in store "teststore" already exists: `+
			"failed to send GET request: failed to send request: "+
			`Get`)
	})
	t.Run("Fail to generate encrypted document ID "+
		"(using deterministic IDs and standard endpoints)", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter)

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("Key", []byte("Value"))
		require.EqualError(t, err, "failed to store data using a deterministic document ID: "+
			"failed to store document using random document ID and standard endpoints: "+
			`failed to generate the encrypted document ID: failed to compute MAC based on key "Key": `+
			"bad key handle format")
	})
	t.Run("Fail to generate formatted key tag (using random IDs and standard endpoints)", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto))
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter)

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("Key", []byte("Value"))
		require.EqualError(t, err, "failed to store data using a random document ID: "+
			`failed to determine if an EDV document for key "Key" in store "teststore" already exists: `+
			`failed to get document ID via key tag query: `+
			`failed to format key tag: failed to compute MAC for tag name "": bad key handle format`)
	})
	t.Run("Fail to create encrypted document for the create document endpoint", func(t *testing.T) {
		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			createValidMACCrypto(t), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter)

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("Key", []byte("Value"))
		require.EqualError(t, err, "failed to store data using a deterministic document ID: "+
			"failed to store document using random document ID and standard endpoints: "+
			"failed to create or update document based on document ID: failed to format tags then create document: "+
			"failed to create document: failed to generate the encrypted document: "+
			"failed to encrypt structured document bytes: failingEncrypter always fails")
	})
}

func TestRESTStore_Get(t *testing.T) {
	t.Run("Fail to decrypt encrypted document", func(t *testing.T) {
		encrypter, _ := createEncrypterAndDecrypter(t)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(encrypter, &failingDecrypter{},
			createValidMACCrypto(t), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter, edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("Key", []byte("Value"))
		require.NoError(t, err)

		value, err := store.Get("Key")
		require.EqualError(t, err, "failed to decrypt encrypted document: failed to get structured document "+
			"from encrypted document bytes: failed to decrypt JWE: failingDecrypter always fails")
		require.Nil(t, value)
	})
}

func TestRESTStore_GetTags(t *testing.T) {
	t.Run("Fail to generate the encrypted document ID", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter)

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		tags, err := store.GetTags("Key")
		require.EqualError(t, err, "failed to get encrypted document stored under a "+
			"deterministic document ID: failed to generate the encrypted document ID: "+
			"failed to format key into an encrypted document ID: "+
			`failed to compute MAC based on key "Key": bad key handle format`)
		require.Nil(t, tags)
	})
	t.Run("Fail to decrypt encrypted document", func(t *testing.T) {
		encrypter, _ := createEncrypterAndDecrypter(t)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(encrypter, &failingDecrypter{},
			createValidMACCrypto(t))
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter)

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("Key", []byte("Value"))
		require.NoError(t, err)

		tags, err := store.GetTags("Key")
		require.EqualError(t, err, "failed to decrypt encrypted document: failed to get structured document "+
			"from encrypted document bytes: failed to decrypt JWE: failingDecrypter always fails")
		require.Nil(t, tags)
	})
}

func TestRESTStore_GetBulk(t *testing.T) {
	t.Run("Unexpected failure while getting value", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		values, err := store.GetBulk("Key")
		require.NotNil(t, err)
		require.Contains(t, err.Error(), `unexpected failure while getting value for key "Key": `+
			"failed to get encrypted document stored under a deterministic document ID: "+
			"failed to retrieve document from EDV server: failed to send GET request: "+
			"failed to send request: ")
		require.Nil(t, values)
	})
}

func TestRESTStore_Query(t *testing.T) {
	t.Run("Fail to format tag for querying", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter, edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		iterator, err := store.Query("TagName:TagValue")
		require.EqualError(t, err, `failed to format tag for querying: `+
			`failed to compute MAC for tag name "TagName": bad key handle format`)
		require.Nil(t, iterator)
	})
	t.Run("Failure while querying EDV server", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		iterator, err := store.Query("TagName:TagValue")
		require.EqualError(t, err, `failure while querying EDV server: failed to send POST request: `+
			`failed to send request: Post "InvalidURL/InvalidVaultID/query": unsupported protocol scheme ""`)
		require.Nil(t, iterator)
	})
	t.Run("Not supported options", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("ServerURL", "VaultID",
			createValidEncryptedFormatter(t))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		iterator, err := store.Query("TagName:TagValue", spi.WithInitialPageNum(1))
		require.EqualError(t, err, "EDV does not support setting the initial page number of query results")
		require.Nil(t, iterator)

		iterator, err = store.Query("TagName:TagValue", spi.WithSortOrder(&spi.SortOptions{}))
		require.EqualError(t, err, "EDV does not support custom sort options for query results")
		require.Nil(t, iterator)
	})
}

func TestRESTStore_Delete(t *testing.T) {
	t.Run("Fail to generate encrypted document ID", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter, edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Delete("Key")
		require.EqualError(t, err, "failed to delete document using deterministic ID: "+
			"failed to generate the encrypted document ID: "+
			`failed to compute MAC based on key "Key": bad key handle format`)
	})
	t.Run("Fail to reach delete endpoint (using deterministic IDs)", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()), edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Delete("Key")
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed to delete document using deterministic ID: "+
			"unexpected failure while deleting document in EDV server: "+
			"failed to send request: Delete")
	})
	t.Run("Fail to determine previously generate random document ID", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t), edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Delete("Key")
		require.EqualError(t, err, "failed to delete document using random ID: "+
			"failed to determine previously generated random document ID: "+
			"failed to get document ID via key tag query: failure while querying EDV server: "+
			"failed to send POST request: failed to send request: "+
			`Post "InvalidURL/InvalidVaultID/query": unsupported protocol scheme ""`)
	})
}

func TestRESTStore_Batch(t *testing.T) {
	t.Run("Fail to generate the encrypted document ID and "+
		"encrypted document bytes (batch extension enabled)", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter, edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key"}})
		require.EqualError(t, err, "failed to batch using batch extension: "+
			"failed to generate vault operations using deterministic IDs: "+
			"failed to generate the encrypted document ID and encrypted document bytes: "+
			"failed to format key into an encrypted document ID: "+
			`failed to compute MAC based on key "Key": bad key handle format`)
	})
	t.Run("Fail to create delete vault operation "+
		"(using random IDs and batch extension enabled)", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto))
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter, edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key"}})
		require.EqualError(t, err, "failed to batch using batch extension: "+
			"failed to create vault operations using random document IDs: "+
			"failed to create vault delete operation: unexpected failure while determining document ID to use: "+
			"unexpected failure while attempting to determine document ID via vault query: "+
			"failed to get document ID via key tag query: "+
			`failed to format key tag: failed to compute MAC for tag name "": bad key handle format`)
	})
	t.Run("Fail to create upsert vault operation "+
		"(using random IDs and batch extension enabled)", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto))
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter, edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key", Value: []byte("Value")}})
		require.EqualError(t, err, "failed to batch using batch extension: "+
			"failed to create vault operations using random document IDs: "+
			"failed to create vault upsert operation: unexpected failure while determining document ID to use: "+
			"unexpected failure while attempting to determine document ID via vault query: "+
			"failed to get document ID via key tag query: "+
			`failed to format key tag: failed to compute MAC for tag name "": bad key handle format`)
	})
	t.Run("Fail to generate document ID (batch extension disabled)", func(t *testing.T) {
		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		failingEncryptedFormatter := edv.NewEncryptedFormatter(&failingEncrypter{}, &failingDecrypter{},
			edv.NewMACCrypto(nil, crypto), edv.WithDeterministicDocumentIDs())
		edvRESTProvider := createEDVRESTProvider(t, failingEncryptedFormatter)

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key", Value: []byte("Value")}})
		require.EqualError(t, err, "failed to batch using standard endpoints: "+
			"failed to execute operation using standard endpoints: "+
			"failed to execute put operation using standard endpoints: "+
			"failed to store data using a deterministic document ID: "+
			"failed to store document using random document ID and standard endpoints: "+
			"failed to generate the encrypted document ID: "+
			`failed to compute MAC based on key "Key": bad key handle format`)
	})
	t.Run("Fail to reach batch endpoint", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()), edv.WithBatchEndpointExtension())

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key", Value: []byte("Value")}})
		require.EqualError(t, err, "failed to batch using batch extension: "+
			"failure while executing batch operation in EDV server: "+
			"failed to send POST request: failed to send request: "+
			`Post "InvalidURL/InvalidVaultID/batch": unsupported protocol scheme ""`)
	})
	t.Run("Fail to reach delete endpoint "+
		"(using deterministic IDs and batch extension is disabled)", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key"}})
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed to batch using standard endpoints: "+
			"failed to execute operation using standard endpoints: "+
			"failed to execute delete operation using standard endpoints: "+
			"failed to delete document using deterministic ID: "+
			"unexpected failure while deleting document in EDV server: "+
			"failed to send request: Delete")
	})
	t.Run("Fail to reach delete endpoint "+
		"(using deterministic IDs and batch extension is disabled)", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key"}})
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed to batch using standard endpoints: "+
			"failed to execute operation using standard endpoints: "+
			"failed to execute delete operation using standard endpoints: "+
			"failed to delete document using deterministic ID: "+
			"unexpected failure while deleting document in EDV server: "+
			"failed to send request: Delete")
	})
	t.Run("Fail to reach query vault endpoint while creating delete document vault operation "+
		"(using random IDs and batch extension is disabled)", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key"}})
		require.EqualError(t, err, "failed to batch using standard endpoints: "+
			"failed to execute operation using standard endpoints: "+
			"failed to execute delete operation using standard endpoints: "+
			"failed to delete document using random ID: "+
			"failed to determine previously generated random document ID: "+
			"failed to get document ID via key tag query: failure while querying EDV server: "+
			`failed to send POST request: failed to send request: Post "InvalidURL/InvalidVaultID/query": `+
			`unsupported protocol scheme ""`)
	})
	t.Run("Fail to reach query vault endpoint while creating upsert document vault operation "+
		"(using random IDs and batch extension is disabled)", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Batch([]spi.Operation{{Key: "Key", Value: []byte("Value")}})
		require.EqualError(t, err, "failed to batch using standard endpoints: "+
			"failed to execute operation using standard endpoints: "+
			"failed to execute put operation using standard endpoints: "+
			"failed to store data using a random document ID: "+
			`failed to determine if an EDV document for key "Key" in store "teststore" already exists: `+
			"failed to get document ID via key tag query: failure while querying EDV server: "+
			`failed to send POST request: failed to send request: Post "InvalidURL/InvalidVaultID/query": `+
			`unsupported protocol scheme ""`)
	})
}

func createEDVRESTProvider(t *testing.T, encryptedFormatter *edv.EncryptedFormatter,
	options ...edv.RESTProviderOption) *edv.RESTProvider {
	options = append(options,
		edv.WithHeaders(func(req *http.Request) (*http.Header, error) {
			req.Header.Set("h1", "v1")
			return &req.Header, nil
		}),
		edv.WithTLSConfig(&tls.Config{ServerName: "name", MinVersion: tls.VersionTLS12}))

	referenceID := uuid.New().String()

	testVaultConfig := `{
  "sequence": 0,
  "controller": "did:example:123456789",
  "referenceId": "` + referenceID + `",
  "kek": {
    "id": "https://example.com/kms/12345",
    "type": "AesKeyWrappingKey2019"
  },
  "hmac": {
    "id": "https://example.com/kms/67891",
    "type": "Sha256HmacKey2019"
  }
}`

	var response *http.Response

	defer func() {
		if response != nil {
			errClose := response.Body.Close()
			if errClose != nil {
				logger.Warnf("failed to close response body: %w", errClose)
			}
		}
	}()

	err := backoff.Retry(func() error {
		var err error

		// We defer outside of the function so we can read the response after we're out of this Retry function.
		response, err =
			http.Post(testServerURL, "", //nolint: bodyclose // false positive
				bytes.NewBuffer([]byte(testVaultConfig)))
		if err != nil {
			logger.Errorf("Failed to send request to create a new data vault. Will retry in one second.")
			return err
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 10))

	require.NoError(t, err, `Failed to create data vault for testing. These unit tests `+
		`require specific CouchDB and EDV docker containers to be running first. `+
		`To run these unit tests, either execute the main unit test script by running `+
		`"make unit-test" (without the quotes) from the root aries-framework-go directory, or, if you want to `+
		`directly run only these EDV REST provider unit tests, run ". scripts/start_edv_test_docker_images.sh" `+
		`(without the quotes) from the root aries-framework-go directory and then try running these unit tests again.`)

	responseBodyBytes, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusCreated, response.StatusCode, string(responseBodyBytes))

	vaultLocation := response.Header.Get("Location")
	vaultID := getVaultIDFromURL(vaultLocation)

	return edv.NewRESTProvider(testServerURL, vaultID, encryptedFormatter, options...)
}

func createValidMACCrypto(t *testing.T) *edv.MACCrypto {
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	require.NoError(t, err)
	require.NotNil(t, kh)

	crypto, err := tinkcrypto.New()
	require.NoError(t, err)

	return edv.NewMACCrypto(kh, crypto)
}

func getVaultIDFromURL(vaultURL string) string {
	splitBySlashes := strings.Split(vaultURL, `/`)
	vaultIDToRetrieve := splitBySlashes[len(splitBySlashes)-1]

	return vaultIDToRetrieve
}

func runCommonTests(t *testing.T, provider spi.Provider) {
	storagetest.TestProviderGetOpenStores(t, provider)
	storagetest.TestProviderOpenStoreSetGetConfig(t, provider)
	storagetest.TestPutGet(t, provider)
	storagetest.TestStoreGetTags(t, provider)
	storagetest.TestStoreGetBulk(t, provider)
	storagetest.TestStoreDelete(t, provider)
	storagetest.TestStoreQuery(t, provider, storagetest.WithIteratorTotalItemCountTests())
	storagetest.TestStoreBatch(t, provider)
	storagetest.TestStoreFlush(t, provider)
	storagetest.TestStoreClose(t, provider)
	storagetest.TestProviderClose(t, provider)
}
