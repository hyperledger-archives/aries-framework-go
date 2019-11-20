/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/storage/jsindexeddb"
)

// WithStorePath return new default store provider instantiate with db path
func WithStorePath(storePath string) aries.Option {
	return func(opts *aries.Aries) error {
		store, err := jsindexeddb.NewProvider()
		if err != nil {
			return err
		}
		return aries.WithStoreProvider(store)(opts)
	}
}
