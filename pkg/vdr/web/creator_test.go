/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
)

func TestCreateDID(t *testing.T) {
	t.Run("test create did failure", func(t *testing.T) {
		v := New()
		d, err := v.Build(nil, create.WithPublicKey(&doc.PublicKey{}))
		require.Nil(t, d)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build not supported in http binding vdr")
	})
}
