// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
)

// WithStorePath return new default store provider instantiate with db path
func WithStorePath(storePath string) aries.Option {
	return func(opts *aries.Aries) error {
		return aries.WithStoreProvider(leveldb.NewProvider(storePath))(opts)
	}
}
