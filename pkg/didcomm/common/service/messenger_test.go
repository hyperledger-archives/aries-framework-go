/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

func TestNewDIDCommContext(t *testing.T) {
	t.Run("returns DIDs and properties", func(t *testing.T) {
		myDID := uuid.New().String()
		theirDID := uuid.New().String()
		propKey := uuid.New().String()
		propValue := uuid.New().String()

		c := service.NewDIDCommContext(myDID, theirDID, map[string]interface{}{
			propKey: propValue,
		})
		require.NotNil(t, c)

		require.Equal(t, myDID, c.MyDID())
		require.Equal(t, theirDID, c.TheirDID())
		p, ok := c.All()[propKey].(string)
		require.True(t, ok)
		require.Equal(t, propValue, p)
	})
}

func TestEmptyDIDCommContext(t *testing.T) {
	t.Run("returns an empty context", func(t *testing.T) {
		c := service.EmptyDIDCommContext()
		require.NotNil(t, c)
		require.Empty(t, c.MyDID())
		require.Empty(t, c.TheirDID())
		require.Empty(t, c.All())
	})
}
