/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestLocalKMSReader(t *testing.T) {
	someKey := []byte("someKeyData")
	someKeyID := "newKeyID"
	storeData := map[string][]byte{
		someKeyID: someKey,
	}

	t.Run("success case - create a valid reader with a non empty and stored keysetID", func(t *testing.T) {
		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{Store: storeData}}

		l := NewReader(leveldbStore, someKeyID)
		require.NotEmpty(t, l)
		data := make([]byte, 512)
		n, err := l.Read(data)
		require.EqualError(t, err, io.EOF.Error())
		require.Equal(t, len(someKey), n)
	})

	t.Run("error case - create an invalid read with empty keysetID", func(t *testing.T) {
		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{Store: storeData}}

		l := NewReader(leveldbStore, "")
		require.NotEmpty(t, l)
		data := make([]byte, 512)
		n, err := l.Read(data)
		require.EqualError(t, err, "keysetID is not set")
		require.Equal(t, 0, n)
	})

	t.Run("error case - create an invalid read with non stored keyset", func(t *testing.T) {
		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{Store: map[string][]byte{}}}

		l := NewReader(leveldbStore, someKeyID)
		require.NotEmpty(t, l)
		data := make([]byte, 512)
		n, err := l.Read(data)
		require.EqualError(t, err, storage.ErrDataNotFound.Error())
		require.Equal(t, 0, n)
	})

	t.Run("success case - create a valid reader with very large keyset data", func(t *testing.T) {
		var veryLargeData []byte
		for i := 0; i <= 1000*1000; i++ {
			veryLargeData = append(veryLargeData, 'a')
		}
		largeStoreData := map[string][]byte{
			someKeyID: veryLargeData,
		}

		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{Store: largeStoreData}}

		l := NewReader(leveldbStore, someKeyID)
		require.NotEmpty(t, l)
		data := make([]byte, 512)
		n, err := l.Read(data)
		require.NoError(t, err)
		// 512 as data capacity is 512 bytes (ie require multiple Read() calls to consume the whole keyset data)
		require.Equal(t, 512, n)
	})
}
