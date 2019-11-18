// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

func TestWithDBPath(t *testing.T) {
	t.Run("test with db path error", func(t *testing.T) {
		// create an non-writeable directory so that the store path will cause error
		tempPath, cleanup := generateTempDir(t)
		defer cleanup()
		err := os.Chmod(tempPath, 0000)
		require.NoError(t, err)

		path := filepath.Join(tempPath, "db")

		_, err = aries.New(WithStorePath(path))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to OpenStore for")
	})

	t.Run("test with db path success", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()
		a, err := aries.New(WithStorePath(path), WithInboundHTTPAddr(":26502", ""))
		require.NoError(t, err)
		require.NoError(t, a.Close())
	})
}

func TestWithInboundHTTPPort(t *testing.T) {
	t.Run("test inbound with http port - success", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		a, err := aries.New(WithStorePath(path), WithInboundHTTPAddr(":26503", ""))
		require.NoError(t, err)
		require.NoError(t, a.Close())
	})

	t.Run("test inbound with http port - empty address", func(t *testing.T) {
		_, err := aries.New(WithInboundHTTPAddr("", ""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "http inbound transport initialization failed")
	})
}

func generateTempDir(t testing.TB) (string, func()) {
	path, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}

	return path, func() {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}
