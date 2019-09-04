/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/stretchr/testify/require"
)

func TestWithDBPath(t *testing.T) {
	t.Run("test with db path error", func(t *testing.T) {
		_, err := WithStorePath("/////////////")
		require.Error(t, err)
		require.Contains(t, err.Error(), "leveldb provider initialization failed")
	})

	t.Run("test with db path success", func(t *testing.T) {
		path, cleanup := setupLevelDB(t)
		defer cleanup()
		defOpt, err := WithStorePath(path)
		require.NoError(t, err)
		a, err := aries.New(defOpt)
		require.NoError(t, err)
		require.NoError(t, a.Close())
	})

}

func setupLevelDB(t testing.TB) (string, func()) {
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
