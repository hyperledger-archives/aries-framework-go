/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	sampleContenttErr  = "sample content err"
	sampleContentValid = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "did:example:123456789abcdefghi",
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp.",
    		"tags": ["professional", "person"],
    		"correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"]
  		}`
	sampleContentInvalid = `{
  			"@context": ["https://w3id.org/wallet/v1"],
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp.",
    		"tags": ["professional", "person"],
    		"correlation": ["4058a72a-9523-11ea-bb37-0242ac130002"]
  		}`
)

func TestContentTypes(t *testing.T) {
	t.Run("test content types", func(t *testing.T) {
		tests := []struct {
			name     string
			inputs   []string
			expected []ContentType
			fail     bool
		}{
			{
				name:     "validation success",
				inputs:   []string{"collection", "credential", "didResolutionResponse", "metadata", "connection"},
				expected: []ContentType{Collection, Credential, DIDResolutionResponse, Metadata, Connection},
			},
			{
				name:   "validation error",
				inputs: []string{"collECtion", "CRED", "VC", "DID", ""},
				fail:   true,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				for i, input := range tc.inputs {
					ct := ContentType(input)

					if tc.fail {
						require.Error(t, ct.IsValid())
						return
					}

					require.NoError(t, ct.IsValid())
					require.Equal(t, tc.expected[i], ct)
					require.Equal(t, ct.Name(), input)
				}
			})
		}
	})
}

func TestContentStores(t *testing.T) {
	t.Run("create new content store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)
		require.EqualValues(t, sp.config.TagNames,
			[]string{"collection", "credential", "connection", "didResolutionResponse", "connection"})
	})

	t.Run("create new content store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sp.failure = errors.New(sampleContenttErr)

		// set store config error
		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.Empty(t, contentStore)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
		require.Contains(t, err.Error(), "failed to set store config for user")

		// open store error
		sp.failure = nil
		sp.ErrOpenStoreHandle = errors.New(sampleContenttErr)

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.Empty(t, contentStore)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
		require.Contains(t, err.Error(), "failed to create store for user")
	})

	t.Run("save to store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(Collection, []byte(sampleContentValid))
		require.NoError(t, err)
	})

	t.Run("save to store - failures", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// invalid content type
		err = contentStore.Save(ContentType("invalid"), []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid content type 'invalid'")

		// invalid content
		err = contentStore.Save(Credential, []byte("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read content to be saved")

		// missing content ID
		err = contentStore.Save(Credential, []byte(sampleContentInvalid))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid wallet content, missing 'id' field")

		// store errors
		sp.Store.ErrPut = errors.New(sampleContenttErr)

		contentStore, err = newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		err = contentStore.Save(Credential, []byte(sampleContentValid))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
	})

	t.Run("get from store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save
		err = contentStore.Save(Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// get
		content, err := contentStore.Get(Collection, "did:example:123456789abcdefghi")
		require.NoError(t, err)
		require.Equal(t, sampleContentValid, string(content))
	})

	t.Run("get from store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sp.Store.ErrGet = errors.New(sampleContenttErr)

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save
		err = contentStore.Save(Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// remove
		content, err := contentStore.Get(Collection, "did:example:123456789abcdefghi")
		require.Empty(t, content)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
	})

	t.Run("remove from store - success", func(t *testing.T) {
		sp := getMockStorageProvider()

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save
		err = contentStore.Save(Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// get
		content, err := contentStore.Get(Collection, "did:example:123456789abcdefghi")
		require.NoError(t, err)
		require.Equal(t, sampleContentValid, string(content))

		// remove
		err = contentStore.Remove(Collection, "did:example:123456789abcdefghi")
		require.NoError(t, err)

		// get
		content, err = contentStore.Get(Collection, "did:example:123456789abcdefghi")
		require.Empty(t, content)
		require.Error(t, err)
		require.True(t, errors.Is(err, storage.ErrDataNotFound))
	})

	t.Run("remove from store - failure", func(t *testing.T) {
		sp := getMockStorageProvider()
		sp.Store.ErrDelete = errors.New(sampleContenttErr)

		contentStore, err := newContentStore(sp, &profile{ID: uuid.New().String()})
		require.NoError(t, err)
		require.NotEmpty(t, contentStore)

		// save
		err = contentStore.Save(Collection, []byte(sampleContentValid))
		require.NoError(t, err)

		// remove
		err = contentStore.Remove(Collection, "did:example:123456789abcdefghi")
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleContenttErr)
	})
}

type mockStorageProvider struct {
	*mockstorage.MockStoreProvider
	config  storage.StoreConfiguration
	failure error
}

func (s *mockStorageProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	s.config = config

	return s.failure
}

func (s *mockStorageProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	return s.config, nil
}

func getMockStorageProvider() *mockStorageProvider {
	return &mockStorageProvider{MockStoreProvider: mockstorage.NewMockStoreProvider()}
}
