/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
)

func TestLocalKMSWriter(t *testing.T) {
	t.Run("success case - create a valid storeWriter and store 20 non empty random keys", func(t *testing.T) {
		keys := map[string][]byte{}
		mockStore := &inMemoryKMSStore{keys: keys}

		for i := 0; i < 256; i++ {
			l := newWriter(mockStore)
			require.NotEmpty(t, l)
			someKey := random.GetRandomBytes(uint32(32))
			n, err := l.Write(someKey)
			require.NoError(t, err)
			require.Equal(t, len(someKey), n)
			require.Equal(t, maxKeyIDLen, len(l.KeysetID), "for key creation iteration %d", i)
			key, ok := keys[l.KeysetID]
			require.True(t, ok)
			require.Equal(t, key, someKey)
		}

		require.Equal(t, 256, len(keys))
	})

	t.Run("error case - create a storeWriter using a bad storeWriter to storage", func(t *testing.T) {
		putErr := fmt.Errorf("failed to put data")
		errGet := kms.ErrKeyNotFound
		mockStore := &mockStore{
			errPut: putErr,
			errGet: errGet,
		}

		l := newWriter(mockStore)
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.EqualError(t, err, putErr.Error())
		require.Equal(t, 0, n)
	})

	t.Run("error case - create a storeWriter using a bad storeReader from storage", func(t *testing.T) {
		errGet := errors.New("failed to get data")
		mockStore := &mockStore{
			errGet: errGet,
		}

		l := newWriter(mockStore)
		require.NotEmpty(t, l)
		someKey := []byte("someKeyData")
		n, err := l.Write(someKey)
		require.EqualError(t, err, errGet.Error())
		require.Equal(t, 0, n)
	})

	t.Run("error case - create a storeWriter with a keysetID using a bad storeReader from storage",
		func(t *testing.T) {
			errGet := errors.New("failed to get data")
			mockStore := &mockStore{
				errGet: errGet,
			}

			l := newWriter(mockStore, kmsapi.WithKeyID(base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(
				uint32(base64.RawURLEncoding.DecodedLen(maxKeyIDLen))))))

			require.NotEmpty(t, l)
			someKey := []byte("someKeyData")
			n, err := l.Write(someKey)
			require.EqualError(t, err, "got error while verifying requested ID: "+errGet.Error())
			require.Equal(t, 0, n)
		})

	t.Run("error case - import duplicate keysetID", func(t *testing.T) {
		mockStore := newInMemoryKMSStore()

		l := newWriter(mockStore)
		require.NotEmpty(t, l)
		someKey := random.GetRandomBytes(uint32(32))
		n, err := l.Write(someKey)
		require.NoError(t, err)
		require.Equal(t, len(someKey), n)
		require.Equal(t, maxKeyIDLen, len(l.KeysetID))
		key, ok := mockStore.keys[l.KeysetID]
		require.True(t, ok)
		require.Equal(t, key, someKey)

		require.Equal(t, 1, len(mockStore.keys))

		// create s second writer with keysetID created above
		l2 := newWriter(mockStore, kmsapi.WithKeyID(l.KeysetID))

		_, err = l2.Write(someKey)
		require.EqualError(t, err, fmt.Sprintf("requested ID '%s' already exists, cannot write keyset",
			l.KeysetID))
	})
}
