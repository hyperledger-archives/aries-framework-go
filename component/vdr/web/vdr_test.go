/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVDRMethods(t *testing.T) {
	t.Run("test base vdr methods", func(t *testing.T) {
		v := New()
		ok := v.Accept("web")
		require.True(t, ok)
		err := v.Close()
		require.Nil(t, err)
	})
}

func TestUpdate(t *testing.T) {
	t.Run("test update", func(t *testing.T) {
		v := New()
		err := v.Update(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})
}

func TestDeactivate(t *testing.T) {
	t.Run("test deactivate", func(t *testing.T) {
		v := New()
		err := v.Deactivate("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})
}
