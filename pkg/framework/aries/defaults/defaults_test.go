/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

func TestWithInboundHTTPPort(t *testing.T) {
	t.Run("test inbound with http port - success", func(t *testing.T) {
		a, err := aries.New(WithInboundHTTPAddr(":26503", "", "", ""))
		require.NoError(t, err)
		require.NoError(t, a.Close())
	})

	t.Run("test inbound with http port - empty address", func(t *testing.T) {
		_, err := aries.New(WithInboundHTTPAddr("", "", "", ""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "http inbound transport initialization failed")
	})
}

func TestWithInboundWSPort(t *testing.T) {
	t.Run("test inbound with ws port - success", func(t *testing.T) {
		a, err := aries.New(WithInboundWSAddr(":26503", "", "", "", 0))
		require.NoError(t, err)
		require.NoError(t, a.Close())
	})

	t.Run("test inbound with ws port - empty address", func(t *testing.T) {
		_, err := aries.New(WithInboundWSAddr("", "", "", "", 0))
		require.Error(t, err)
		require.Contains(t, err.Error(), "ws inbound transport initialization failed")
	})
}

func TestWithInboundWebSocketReadLimit(t *testing.T) {
	a, err := aries.New(WithInboundWSAddr(":26503", "", "", "", 65536))
	require.NoError(t, err)
	require.NoError(t, a.Close())
}
