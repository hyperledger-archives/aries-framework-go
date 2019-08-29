/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/config/lookup"
)

var configYAML = `
test:
  key1: value1
`

var wrongConfigYAML = `
   ww"
`

func TestFromReader(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte(configYAML))
		configBackend, err := FromReader(buf, "yaml")()
		require.NoError(t, err)
		c := lookup.New(configBackend)
		v := c.GetString("test.key1")
		require.Equal(t, "value1", v)
		v = c.GetString("test.key2")
		require.Empty(t, v)
	})

	t.Run("test error loading config", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte(wrongConfigYAML))
		_, err := FromReader(buf, "yaml")()
		require.Error(t, err)
		require.Contains(t, err.Error(), "viper MergeConfig failed")
	})

	t.Run("test config type is empty", func(t *testing.T) {
		_, err := FromReader(nil, "")()
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty config type")
	})
}

func TestFromFile(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "config-*.yaml")
		defer func() { require.NoError(t, file.Close()); require.NoError(t, os.Remove(file.Name())) }()
		require.NoError(t, err)
		_, err = file.WriteString(configYAML)
		require.NoError(t, err)
		configBackend, err := FromFile(file.Name())()
		require.NoError(t, err)
		c := lookup.New(configBackend)
		v := c.GetString("test.key1")
		require.Equal(t, "value1", v)
		v = c.GetString("test.key2")
		require.Empty(t, v)
	})

	t.Run("test file name is empty", func(t *testing.T) {
		_, err := FromFile("")()
		require.Error(t, err)
		require.Contains(t, err.Error(), "filename is required")
	})

	t.Run("test error loading config", func(t *testing.T) {
		_, err := FromFile("file")()
		require.Error(t, err)
		require.Contains(t, err.Error(), "loading config file failed")
	})
}

func TestWithEnvPrefix(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte(configYAML))
		configBackend, err := FromReader(buf, "yaml", WithEnvPrefix(""))()
		require.NoError(t, err)
		c := lookup.New(configBackend)
		v := c.GetString("test.key1")
		require.Equal(t, "value1", v)
		v = c.GetString("test.key2")
		require.Empty(t, v)
	})
}
