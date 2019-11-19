// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultFramework(t *testing.T) {
	t.Run("test default framework - success", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		aries := &Aries{}

		err := defFrameworkOpts(aries)
		require.NoError(t, err)
	})

	t.Run("test default framework - inbound transport error", func(t *testing.T) {
		currentInboundPort := defaultInboundPort
		defer func() { defaultInboundPort = currentInboundPort }()

		path, cleanup := generateTempDir(t)
		defer cleanup()
		dbPath = path

		defaultInboundPort = ""

		aries := &Aries{}

		err := defFrameworkOpts(aries)
		require.Error(t, err)
		require.Contains(t, err.Error(), "http inbound transport initialization failed")
	})
}
