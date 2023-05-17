/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
)

func TestUpdate(t *testing.T) {
	t.Run("test update", func(t *testing.T) {
		v, err := New(&storage.MockStoreProvider{})
		require.NoError(t, err)

		err = v.Update(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})
}

func TestDeactivate(t *testing.T) {
	t.Run("test deactivate", func(t *testing.T) {
		v, err := New(&storage.MockStoreProvider{})
		require.NoError(t, err)

		err = v.Deactivate("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})
}
