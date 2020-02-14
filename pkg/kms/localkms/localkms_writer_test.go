/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestLocalKMSWriter(t *testing.T) {
	masterKeyURI := "/master/key/uri"

	t.Run("success case - create a valid storeWriter and store a non empty key", func(t *testing.T) {
		storeMap := map[string][]byte{}
		mockStore := &mockstorage.MockStore{Store: storeMap}

		l := newWriter(mockStore, masterKeyURI)
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.NoError(t, err)
		require.Equal(t, len(someKey), n)
		require.NotEmpty(t, l.KeysetID)
		retrievedKey, ok := storeMap[l.KeysetID]
		require.True(t, ok)
		require.Equal(t, retrievedKey, someKey)
	})

	t.Run("error case - create a storeWriter with missing mastKeyURI", func(t *testing.T) {
		storeMap := map[string][]byte{}
		mockStore := &mockstorage.MockStore{Store: storeMap}

		l := newWriter(mockStore, "")
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.EqualError(t, err, "master key is not set")
		require.Equal(t, 0, n)
	})

	t.Run("error case - create a storeWriter using a bad storeWriter to storage", func(t *testing.T) {
		storeMap := map[string][]byte{}
		putError := fmt.Errorf("failed to put data")
		mockStore := &mockstorage.MockStore{
			Store:  storeMap,
			ErrPut: putError,
		}

		l := newWriter(mockStore, masterKeyURI)
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.EqualError(t, err, putError.Error())
		require.Equal(t, 0, n)
	})

	t.Run("error case - create a storeWriter using a bad storeReader from storage", func(t *testing.T) {
		storeMap := map[string][]byte{}
		getError := fmt.Errorf("failed to get data")
		mockStore := &mockstorage.MockStore{
			Store:  storeMap,
			ErrGet: getError,
		}

		l := newWriter(mockStore, masterKeyURI)
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.EqualError(t, err, getError.Error())
		require.Equal(t, 0, n)
	})
}
