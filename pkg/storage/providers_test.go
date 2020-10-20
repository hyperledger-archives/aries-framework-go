// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

func setUpProviders(t *testing.T) []Provider {
	t.Helper()

	var providers []Provider

	providers = append(providers,
		Provider{Provider: mem.NewProvider(), Name: "Mem"},
	)

	dbPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}

	t.Cleanup(func() {
		err = os.RemoveAll(dbPath)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	})

	providers = append(providers, Provider{
		Provider: leveldb.NewProvider(dbPath), Name: "LevelDB",
	})

	return providers
}
