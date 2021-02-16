/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestLocalKMSReader(t *testing.T) {
	someKey := []byte("someKeyData")
	someKeyID := "newKeyID"
	storeData := map[string]mockstorage.DBEntry{
		someKeyID: {Value: someKey},
	}

	t.Run("success case - create a valid storeReader with a non empty and stored keysetID", func(t *testing.T) {
		localStore := &mockstorage.MockStore{Store: storeData}

		l := newReader(localStore, someKeyID)
		require.NotEmpty(t, l)
		data := make([]byte, 512)
		n, err := l.Read(data)
		require.NoError(t, err)
		require.Equal(t, len(someKey), n)

		// try to read again - should return io.EOF
		n, err = l.Read(data)
		require.EqualError(t, err, io.EOF.Error())
		require.Equal(t, n, 0)
	})

	t.Run("error case - create an invalid read with empty keysetID", func(t *testing.T) {
		mockStore := &mockstorage.MockStore{Store: storeData}

		l := newReader(mockStore, "")
		require.NotEmpty(t, l)
		data := make([]byte, 512)
		n, err := l.Read(data)
		require.EqualError(t, err, "keysetID is not set")
		require.Equal(t, 0, n)
	})

	t.Run("error case - create an invalid read with non stored keyset", func(t *testing.T) {
		mockStore := &mockstorage.MockStore{Store: map[string]mockstorage.DBEntry{}}

		l := newReader(mockStore, someKeyID)
		require.NotEmpty(t, l)
		data := make([]byte, 512)
		n, err := l.Read(data)
		require.EqualError(t, err,
			fmt.Errorf("cannot read data for keysetID %s: %w", someKeyID, storage.ErrDataNotFound).Error())
		require.Equal(t, 0, n)
	})

	t.Run("success case - create a valid storeReader with very large keyset data", func(t *testing.T) {
		var veryLargeData []byte
		dataLen := 1000 * 1000
		blockSize := 512
		for i := 0; i < dataLen; i++ {
			veryLargeData = append(veryLargeData, 'a')
		}
		largeStoreData := map[string]mockstorage.DBEntry{
			someKeyID: {Value: veryLargeData},
		}

		mockStore := &mockstorage.MockStore{Store: largeStoreData}

		l := newReader(mockStore, someKeyID)
		require.NotEmpty(t, l)
		data := make([]byte, blockSize)
		bytesRead := 0
		var readData []byte
		for bytesRead < dataLen-blockSize {
			n, err := l.Read(data)
			require.NoError(t, err)
			// data has capacity of 512 bytes (ie require multiple Read() calls to consume the whole keyset data)
			require.Equal(t, blockSize, n)
			bytesRead += n
			readData = append(readData, data...)
		}

		// last read..
		n, err := l.Read(data)
		require.NoError(t, err)
		// append remainder data read
		readData = append(readData, data[:n]...)
		// data has capacity of blockSize bytes, last read would be the remainder chunk of dataLen which is smaller
		// than blockSize bytes
		require.Equal(t, dataLen%blockSize, n)
		require.Equal(t, len(readData), dataLen)

		// try to read one more time, should return an error
		n, err = l.Read(data)
		require.EqualError(t, err, io.EOF.Error())
		require.Equal(t, n, 0)
	})
}
