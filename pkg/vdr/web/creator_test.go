/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

func TestCreateDID(t *testing.T) {
	t.Run("test create did failure", func(t *testing.T) {
		v := New()
		doc, err := v.Build(&vdr.PubKey{})
		require.Nil(t, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build not supported in http binding vdr")
	})
}
