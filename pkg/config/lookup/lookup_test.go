/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lookup

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_GetString(t *testing.T) {
	t.Run("test value found", func(t *testing.T) {
		c := New(&mockConfigBackend{lookupValue: "value1", lookupValueFound: true})
		v := c.GetString("key1")
		require.Equal(t, "value1", v)
	})
	t.Run("test value not found", func(t *testing.T) {
		c := New(&mockConfigBackend{lookupValueFound: false})
		v := c.GetString("key1")
		require.Equal(t, "", v)
	})
}

func Test_GetBool(t *testing.T) {
	t.Run("test value found", func(t *testing.T) {
		c := New(&mockConfigBackend{lookupValue: true, lookupValueFound: true})
		v := c.GetBool("key1")
		require.True(t, v)
	})
	t.Run("test value not found", func(t *testing.T) {
		c := New(&mockConfigBackend{lookupValueFound: false})
		v := c.GetBool("key1")
		require.False(t, v)
	})
}

func Test_GetInt(t *testing.T) {
	t.Run("test value found", func(t *testing.T) {
		c := New(&mockConfigBackend{lookupValue: 1, lookupValueFound: true})
		v := c.GetInt("key1")
		require.Equal(t, 1, v)
	})
	t.Run("test value not found", func(t *testing.T) {
		c := New(&mockConfigBackend{lookupValueFound: false})
		v := c.GetInt("key1")
		require.Equal(t, 0, v)
	})
}

func Test_GetDuration(t *testing.T) {
	t.Run("test value found", func(t *testing.T) {
		c := New(&mockConfigBackend{lookupValue: 1 * time.Second, lookupValueFound: true})
		v := c.GetDuration("key1")
		require.Equal(t, 1*time.Second, v)
	})
	t.Run("test value not found", func(t *testing.T) {
		c := New(&mockConfigBackend{lookupValueFound: false})
		v := c.GetDuration("key1")
		require.Equal(t, 0*time.Second, v)
	})
}

type mockConfigBackend struct {
	lookupValue      interface{}
	lookupValueFound bool
}

func (m *mockConfigBackend) Lookup(key string) (interface{}, bool) {
	return m.lookupValue, m.lookupValueFound
}
