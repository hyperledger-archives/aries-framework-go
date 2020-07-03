/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIntroduce_Actions(t *testing.T) {
	t.Run("test it performs an actions request", func(t *testing.T) {
		a, err := NewAries()
		require.NoError(t, err)

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		i, ok := ic.(*Introduce)
		require.Equal(t, ok, true)

		resp := i.Actions(nil)
		require.NotNil(t, resp)
	})
}
