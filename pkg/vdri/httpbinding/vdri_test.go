/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVDRI_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New("/did:example:334455")
		require.NoError(t, err)
		require.NoError(t, v.Close())
	})
}

func TestVDRI_Store(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New("/did:example:334455")
		require.NoError(t, err)
		err = v.Store(nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})
}

func TestVDRI_Build(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New("/did:example:334455")
		require.NoError(t, err)
		_, err = v.Build(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})
}
