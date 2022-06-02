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
	commonTestOptions := []storagetest.TestOption{
		storagetest.SkipSortTests(false),
		storagetest.SkipOpenStoreSetGetStoreConfigTests(),
	}

	t.Run("With random document IDs", func(t *testing.T) {
		t.Run("Without batch endpoint extension", func(t *testing.T) {
			t.Run(`Without "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t, createValidEncryptedFormatter(t))
				runCommonTests(t, edvRESTProvider, commonTestOptions)
			})
			t.Run(`With "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t, createValidEncryptedFormatter(t),
					edv.WithFullDocumentsReturnedFromQueries())
				runCommonTests(t, edvRESTProvider, commonTestOptions)
			})
		})
		t.Run("With batch endpoint extension", func(t *testing.T) {
			t.Run(`Without "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t, createValidEncryptedFormatter(t),
					edv.WithBatchEndpointExtension())
				runCommonTests(t, edvRESTProvider, commonTestOptions)
			})
			t.Run(`With "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t, createValidEncryptedFormatter(t),
					edv.WithBatchEndpointExtension(),
					edv.WithFullDocumentsReturnedFromQueries())
				runCommonTests(t, edvRESTProvider, commonTestOptions)
			})
		})
	})
	t.Run("With deterministic document IDs", func(t *testing.T) {
		t.Run("Without batch endpoint extension", func(t *testing.T) {
			t.Run(`Without "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t,
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()))
				runCommonTests(t, edvRESTProvider, commonTestOptions)
			})
			t.Run(`With "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t,
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()),
					edv.WithFullDocumentsReturnedFromQueries())
				runCommonTests(t, edvRESTProvider, commonTestOptions)
			})
		})
		t.Run("With batch endpoint extension", func(t *testing.T) {
			t.Run(`Without "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t,
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()),
					edv.WithBatchEndpointExtension())
				runCommonTests(t, edvRESTProvider, commonTestOptions)
			})
			t.Run(`With "return full documents from queries" extension`, func(t *testing.T) {
				edvRESTProvider := createEDVRESTProvider(t,
					createValidEncryptedFormatter(t, edv.WithDeterministicDocumentIDs()),
					edv.WithBatchEndpointExtension(),
					edv.WithFullDocumentsReturnedFromQueries())
				runCommonTests(t, edvRESTProvider, commonTestOptions)
			})
		})
	})
}

func runCommonTests(t *testing.T, provider spi.Provider, commonTestOptions []storagetest.TestOption) {
	storagetest.TestAll(t, provider, commonTestOptions...)
	testQueryWithMultipleTags(t, provider)
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
		kmsSvc, cryptoSvc := createKMSAndCrypto(t)
		encrypter, _, _ := createEncrypterAndDecrypter(t, kmsSvc, cryptoSvc)

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
		kmsSvc, cryptoSvc := createKMSAndCrypto(t)
		encrypter, _, _ := createEncrypterAndDecrypter(t, kmsSvc, cryptoSvc)

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
	t.Run("Failure while querying vault", func(t *testing.T) {
		edvRESTProvider := edv.NewRESTProvider("InvalidURL", "InvalidVaultID",
			createValidEncryptedFormatter(t))

		store, err := edvRESTProvider.OpenStore("TestStore")
		require.NoError(t, err)

		iterator, err := store.Query("TagName:TagValue")
		require.EqualError(t, err, `failure while querying vault: failed to send POST request: `+
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

func testQueryWithMultipleTags(t *testing.T, provider spi.Provider) { //nolint:gocyclo // test file
	t.Helper()

	defer func() {
		require.NoError(t, provider.Close())
	}()

	keysToPut, valuesToPut, tagsToPut := getTestData()

	storeName := randomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	putData(t, store, keysToPut, valuesToPut, tagsToPut)

	t.Run("AND queries", func(t *testing.T) {
		t.Run("Two tag name + value pairs - 2 values found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"Breed:GoldenRetriever&&Personality:Calm",
				"Personality:Calm&&Breed:GoldenRetriever", // Should be equivalent to the above expression
			}

			expectedKeys, expectedValues, expectedTags := getExpectedData([]int{3, 4})

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, len(expectedKeys))
			}
		})
		t.Run("Two tag name + value pairs - 1 value found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"Personality:Shy&&EarType:Pointy",
				"EarType:Pointy&&Personality:Shy", // Should be equivalent to the above expression
			}

			expectedKeys, expectedValues, expectedTags := getExpectedData([]int{1})

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, len(expectedKeys))
			}
		})
		t.Run("Two tag name + value pairs - 0 values found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"Personality:Crazy&&EarType:Pointy",
				"EarType:Pointy&&Personality:Crazy", // Should be equivalent to the above expression
			}

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, nil, nil, nil, 0)
			}
		})
		t.Run("One tag name + value pair and an additional tag name - 1 value found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"EarType:Pointy&&Nickname",
				"Nickname&&EarType:Pointy", // Should be equivalent to the above expression
			}

			expectedKeys, expectedValues, expectedTags := getExpectedData([]int{2})

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, len(expectedKeys))
			}
		})
		t.Run("One tag name + value pair and an additional tag name - 0 values found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"EarType:Pointy&&CoatType",
				"CoatType&&EarType:Pointy", // Should be equivalent to the above expression
			}

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, nil, nil, nil, 0)
			}
		})
		t.Run("Three tag name + values pairs - 3 values found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"Breed:GoldenRetriever&&NumLegs:4&&EarType:Floppy",
				"NumLegs:4&&EarType:Floppy&&Breed:GoldenRetriever", // Should be equivalent to the above expression
			}

			expectedKeys, expectedValues, expectedTags := getExpectedData([]int{0, 3, 4})

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, len(expectedKeys))
			}
		})
	})
	t.Run("OR queries", func(t *testing.T) {
		t.Run("Two tag name + value pairs - 2 values found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"Breed:GoldenRetriever||Nickname:Fluffball",
				"Nickname:Fluffball||Breed:GoldenRetriever", // Should be equivalent to the above expression
			}

			expectedKeys, expectedValues, expectedTags := getExpectedData([]int{0, 2, 3, 4})

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, len(expectedKeys))
			}
		})
		t.Run("One tag name + value pair and an additional tag name - 3 values found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"Nickname||Breed:Schweenie",
				"Breed:Schweenie||Nickname", // Should be equivalent to the above expression
			}

			expectedKeys, expectedValues, expectedTags := getExpectedData([]int{0, 1, 2})

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, len(expectedKeys))
			}
		})
		t.Run("Three tag name + values pairs - 4 values found", func(t *testing.T) {
			queryExpressionsToTest := []string{
				"Breed:GoldenRetriever||Nickname:Fluffball||Age:1",
				"Age:1||Nickname:Fluffball||Breed:GoldenRetriever", // Should be equivalent to the above expression
			}

			expectedKeys, expectedValues, expectedTags := getExpectedData([]int{0, 1, 2, 3, 4})

			for _, queryExpressionToTest := range queryExpressionsToTest {
				iterator, err := store.Query(queryExpressionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, len(expectedKeys))
			}
		})
	})
	t.Run("AND+OR combined query", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Breed:GoldenRetriever&&Personality:Calm||Nickname:Fluffball",
			"Nickname:Fluffball||Breed:GoldenRetriever&&Personality:Calm", // Should be equivalent to the above expression
		}

		expectedKeys, expectedValues, expectedTags := getExpectedData([]int{2, 3, 4})

		for _, queryExpressionToTest := range queryExpressionsToTest {
			iterator, err := store.Query(queryExpressionToTest)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, len(expectedKeys))
		}
	})
}

func getTestData() (testKeys []string, testValues [][]byte, testTags [][]spi.Tag) {
	testKeys = []string{
		"Cassie",
		"Luna",
		"Miku",
		"Amber",
		"Brandy",
	}

	testValues = [][]byte{
		[]byte("is a big, young dog"),
		[]byte("is a small dog"),
		[]byte("is a fluffy dog (also small)"),
		[]byte("is a big, old dog"),
		[]byte("is a big dog of unknown age (but probably old)"),
	}

	testTags = [][]spi.Tag{
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Playful"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
			{Name: "Nickname", Value: "Miss"},
			{Name: "Age", Value: "2"},
		},
		{
			{Name: "Breed", Value: "Schweenie"},
			{Name: "Personality", Value: "Shy"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Pointy"},
			{Name: "Age", Value: "1"},
		},
		{
			{Name: "Breed", Value: "Pomchi"},
			{Name: "Personality", Value: "Outgoing"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Pointy"},
			{Name: "Nickname", Value: "Fluffball"},
			{Name: "Age", Value: "1"},
		},
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Calm"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
			{Name: "Age", Value: "14"},
		},
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Calm"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
		},
	}

	return testKeys, testValues, testTags
}

func getExpectedData(expectedIndexes []int) (expectedKeys []string, expectedValues [][]byte, expectedTags [][]spi.Tag) {
	keys, values, tags := getTestData()

	expectedKeys = make([]string, len(expectedIndexes))
	expectedValues = make([][]byte, len(expectedIndexes))
	expectedTags = make([][]spi.Tag, len(expectedIndexes))

	for i, expectedIndex := range expectedIndexes {
		expectedKeys[i] = keys[expectedIndex]
		expectedValues[i] = values[expectedIndex]
		expectedTags[i] = tags[expectedIndex]
	}

	return expectedKeys, expectedValues, expectedTags
}

func putData(t *testing.T, store spi.Store, keys []string, values [][]byte, tags [][]spi.Tag) {
	t.Helper()

	for i := 0; i < len(keys); i++ {
		err := store.Put(keys[i], values[i], tags[i]...)
		require.NoError(t, err)
	}
}

// expectedKeys, expectedValues, and expectedTags are with respect to the query's page settings.
// Since Iterator.TotalItems' count is not affected by page settings, expectedTotalItemsCount must be passed in and
// can't be determined by looking at the length of expectedKeys, expectedValues, nor expectedTags.
func verifyExpectedIterator(t *testing.T, actualResultsItr spi.Iterator, //nolint:gocognit, gocyclo // test file
	expectedKeys []string, expectedValues [][]byte, expectedTags [][]spi.Tag, expectedTotalItemsCount int) {
	t.Helper()

	if len(expectedValues) != len(expectedKeys) || len(expectedTags) != len(expectedKeys) {
		require.FailNow(t,
			"Invalid test case. Expected keys, values and tags slices must be the same length.")
	}

	t.Helper()

	var dataChecklist struct {
		keys     []string
		values   [][]byte
		tags     [][]spi.Tag
		received []bool
	}

	dataChecklist.keys = expectedKeys
	dataChecklist.values = expectedValues
	dataChecklist.tags = expectedTags
	dataChecklist.received = make([]bool, len(expectedKeys))

	moreResultsToCheck, err := actualResultsItr.Next()
	require.NoError(t, err)

	if !moreResultsToCheck && len(expectedKeys) != 0 {
		require.FailNow(t, "query unexpectedly returned no results")
	}

	for moreResultsToCheck {
		dataReceivedCount := 0

		for _, received := range dataChecklist.received {
			if received {
				dataReceivedCount++
			}
		}

		if dataReceivedCount == len(dataChecklist.received) {
			require.FailNow(t, "iterator contains more results than expected")
		}

		var itrErr error
		receivedKey, itrErr := actualResultsItr.Key()
		require.NoError(t, itrErr)

		receivedValue, itrErr := actualResultsItr.Value()
		require.NoError(t, itrErr)

		receivedTags, itrErr := actualResultsItr.Tags()
		require.NoError(t, itrErr)

		for i := 0; i < len(dataChecklist.keys); i++ {
			if receivedKey == dataChecklist.keys[i] {
				if string(receivedValue) == string(dataChecklist.values[i]) {
					if equalTags(receivedTags, dataChecklist.tags[i]) {
						dataChecklist.received[i] = true

						break
					}
				}
			}
		}

		moreResultsToCheck, err = actualResultsItr.Next()
		require.NoError(t, err)
	}

	count, errTotalItems := actualResultsItr.TotalItems()
	require.NoError(t, errTotalItems)
	require.Equal(t, expectedTotalItemsCount, count)

	err = actualResultsItr.Close()
	require.NoError(t, err)

	for _, received := range dataChecklist.received {
		if !received {
			require.FailNow(t, "received unexpected query results")
		}
	}
}

func equalTags(tags1, tags2 []spi.Tag) bool { //nolint:gocyclo // Test file
	if len(tags1) != len(tags2) {
		return false
	}

	matchedTags1 := make([]bool, len(tags1))
	matchedTags2 := make([]bool, len(tags2))

	for i, tag1 := range tags1 {
		for j, tag2 := range tags2 {
			if matchedTags2[j] {
				continue // This tag has already found a match. Tags can only have one match!
			}

			if tag1.Name == tag2.Name && tag1.Value == tag2.Value {
				matchedTags1[i] = true
				matchedTags2[j] = true

				break
			}
		}

		if !matchedTags1[i] {
			return false
		}
	}

	for _, matchedTag := range matchedTags1 {
		if !matchedTag {
			return false
		}
	}

	for _, matchedTag := range matchedTags2 {
		if !matchedTag {
			return false
		}
	}

	return true
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

		// We defer outside the function, so we can read the response after we're out of this Retry function.
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
		`require specific MongoDB and EDV docker containers to be running first. `+
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

func randomStoreName() string {
	return "store-" + uuid.New().String()
}
