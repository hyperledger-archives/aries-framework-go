/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

func TestBaseWallet_New(t *testing.T) {
	t.Run("test error from GetStoreHandle", func(t *testing.T) {
		_, err := New(&mockstorage.MockStoreProvider{ErrGetStoreHandle: fmt.Errorf("error from GetStoreHandle")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error from GetStoreHandle")
	})
}

func TestBaseWallet_CreateKey(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}})
		require.NoError(t, err)
		verKey, err := w.CreateKey()
		require.NoError(t, err)
		require.NotEmpty(t, verKey)

	})

	t.Run("test error from persistKey", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte), ErrPut: fmt.Errorf("put error"),
		}})
		require.NoError(t, err)
		_, err = w.CreateKey()
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})
}

func TestBaseWallet_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{})
		require.NoError(t, err)
		require.NoError(t, w.Close())
	})
}

func TestBaseWallet_UnpackMessage(t *testing.T) {
	t.Run("test error not implemented", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{})
		require.NoError(t, err)
		_, err = w.UnpackMessage(nil)
		require.Error(t, err)
	})
}

func TestBaseWallet_PackMessage(t *testing.T) {
	t.Run("test error not implemented", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{})
		require.NoError(t, err)
		_, err = w.PackMessage(nil)
		require.Error(t, err)
	})
}

func TestBaseWallet_SignMessage(t *testing.T) {
	t.Run("test error not implemented", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{})
		require.NoError(t, err)
		_, err = w.SignMessage(nil, "")
		require.Error(t, err)
	})
}

func TestBaseWallet_DecryptMessage(t *testing.T) {
	t.Run("test error not implemented", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{})
		require.NoError(t, err)
		_, _, err = w.DecryptMessage(nil, "")
		require.Error(t, err)
	})
}
