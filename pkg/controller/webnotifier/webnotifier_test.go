/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webnotifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("New WebNotifier (populated)", func(t *testing.T) {
		n := New("/", []string{"http://localhost:8080"})
		require.NotNil(t, n)
		require.Equal(t, 2, len(n.notifiers))
		require.Equal(t, 1, len(n.handlers))
	})

	t.Run("New WebNotifier (nil)", func(t *testing.T) {
		n := New("", nil)
		require.NotNil(t, n)
		require.Equal(t, 2, len(n.notifiers))
		require.Equal(t, 1, len(n.handlers))
	})
}

func TestNotify(t *testing.T) {
	n := New("/", []string{"http://localhost:8080"})
	require.NotNil(t, n)

	err := n.Notify("example", []byte("payload"))
	require.Error(t, err)
}

func TestGetHandlers(t *testing.T) {
	n := New("/", []string{"http://localhost:8080"})
	require.NotNil(t, n)

	handlers := n.GetRESTHandlers()
	require.Equal(t, 1, len(handlers))
}
