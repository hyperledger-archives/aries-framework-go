/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

func TestLocalKMSWriter(t *testing.T) {
	masterKeyURI := "/master/key/uri"

	t.Run("success case - create a valid writer and store a non empty key", func(t *testing.T) {
		storeMap := map[string][]byte{}
		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{Store: storeMap}}

		l := NewWriter(leveldbStore, masterKeyURI)
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

	t.Run("error case - create a writer with missing mastKeyURI", func(t *testing.T) {
		storeMap := map[string][]byte{}
		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{Store: storeMap}}

		l := NewWriter(leveldbStore, "")
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.EqualError(t, err, "master key is not set")
		require.Equal(t, 0, n)
	})

	t.Run("error case - create a writer using a bad writer to storage", func(t *testing.T) {
		storeMap := map[string][]byte{}
		putError := fmt.Errorf("failed to put data")
		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{
				Store:  storeMap,
				ErrPut: putError,
			}}

		l := NewWriter(leveldbStore, masterKeyURI)
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.EqualError(t, err, putError.Error())
		require.Equal(t, 0, n)
	})

	t.Run("error case - create a writer using a bad reader from storage", func(t *testing.T) {
		storeMap := map[string][]byte{}
		getError := fmt.Errorf("failed to get data")
		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{
				Store:  storeMap,
				ErrGet: getError,
			}}

		l := NewWriter(leveldbStore, masterKeyURI)
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.EqualError(t, err, getError.Error())
		require.Equal(t, 0, n)
	})
}
