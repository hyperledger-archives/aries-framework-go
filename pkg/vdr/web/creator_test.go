/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateDID(t *testing.T) {
	t.Run("test create did failure", func(t *testing.T) {
		v := New()
		d, err := v.Create(nil, nil)
		require.Nil(t, d)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build not supported in http binding vdr")
	})
}
