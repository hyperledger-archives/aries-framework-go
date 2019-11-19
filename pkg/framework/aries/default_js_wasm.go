/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/jsindexeddb"
)

func storeProvider() (storage.Provider, error) {
	storeProv, err := jsindexeddb.NewProvider(dbPath)
	if err != nil {
		return nil, fmt.Errorf("js indexeddb provider initialization failed : %w", err)
	}

	return storeProv, nil
}

func transientStoreProvider() (storage.Provider, error) {
	storeProv, err := jsindexeddb.NewProvider(dbPath)
	if err != nil {
		return nil, fmt.Errorf("js indexeddb  provider initialization failed : %w", err)
	}

	return storeProv, nil
}
