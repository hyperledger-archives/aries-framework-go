// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage/jsindexeddb"
)

func setUpProviders(t *testing.T) []Provider {
	t.Helper()

	provider, err := jsindexeddb.NewProvider("js-db")
	require.NoError(t, err)

	return []Provider{{
		Provider: provider, Name: "IndexedDB",
	}}
}
