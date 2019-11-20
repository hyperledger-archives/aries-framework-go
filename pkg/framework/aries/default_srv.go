// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

//nolint:gochecknoglobals
var (
	// DBPath Level DB Path.
	dbPath = "/tmp/peerstore/"
)

func storeProvider() (storage.Provider, error) {
	return leveldb.NewProvider(dbPath), nil
}

func transientStoreProvider() (storage.Provider, error) {
	return mem.NewProvider(), nil
}
