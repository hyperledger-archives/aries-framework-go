/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

func TestStoreDID(t *testing.T) {
	t.Run("test store did failure", func(t *testing.T) {
		v := New()
		err := v.Store(&did.Doc{})
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "store not supported in http binding vdr")
	})
}
