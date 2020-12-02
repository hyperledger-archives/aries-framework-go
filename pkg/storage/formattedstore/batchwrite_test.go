/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage/formattedstore"
)

func TestNewBatchWrite(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s := formattedstore.NewBatchWrite(1, 10*time.Second, createEDVFormatter(t), newMockStoreProvider())

		err := s.Put(&mockStore{}, "k1", []byte("v1"))
		require.NoError(t, err)

		v, err := s.Get("k1")
		require.NoError(t, err)
		require.Equal(t, "v1", string(v))

		time.Sleep(2 * time.Second)

		err = s.Put(&mockStore{}, "k2", []byte("v2"))
		require.NoError(t, err)

		_, err = s.Get("k1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "k k1 not found")
	})

	t.Run("success delete", func(t *testing.T) {
		s := formattedstore.NewBatchWrite(1, 10*time.Second, createEDVFormatter(t), newMockStoreProvider())

		err := s.Put(&mockStore{}, "k1", []byte("v1"))
		require.NoError(t, err)

		v, err := s.Get("k1")
		require.NoError(t, err)
		require.Equal(t, "v1", string(v))

		s.Delete("k1")

		_, err = s.Get("k1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "value is deleted")
	})

	t.Run("success flush using time batch", func(t *testing.T) {
		s := formattedstore.NewBatchWrite(4, 1*time.Second, createEDVFormatter(t), newMockStoreProvider())

		err := s.Put(&mockStore{}, "k1", []byte("v1"))
		require.NoError(t, err)

		v, err := s.Get("k1")
		require.NoError(t, err)
		require.Equal(t, "v1", string(v))

		time.Sleep(2 * time.Second)

		_, err = s.Get("k1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "k k1 not found")
	})

	t.Run("error from flush", func(t *testing.T) {
		s := formattedstore.NewBatchWrite(1, 10*time.Second, createEDVFormatter(t),
			&mockStoreProvider{batchErr: fmt.Errorf("failed to put")})

		err := s.Put(&mockStore{}, "k1", []byte("v1"))
		require.NoError(t, err)

		v, err := s.Get("k1")
		require.NoError(t, err)
		require.Equal(t, "v1", string(v))

		time.Sleep(1 * time.Second)

		err = s.Put(&mockStore{}, "k2", []byte("v2"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to put")
	})
}
