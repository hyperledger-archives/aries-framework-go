/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
)

// WithStorePath return new default store provider instantiate with db path
func WithStorePath(storePath string) aries.Option {
	return func(opts *aries.Aries) error {
		storeProv, err := leveldb.NewProvider(storePath)
		if err != nil {
			return fmt.Errorf("leveldb provider initialization failed : %w", err)
		}
		return aries.WithStoreProvider(storeProv)(opts)
	}
}

// WithInboundHTTPAddr return new default inbound transport.
func WithInboundHTTPAddr(internalAddr, externalAddr string) aries.Option {
	return func(opts *aries.Aries) error {
		inbound, err := http.NewInbound(internalAddr, externalAddr)
		if err != nil {
			return fmt.Errorf("http inbound transport initialization failed : %w", err)
		}
		return aries.WithInboundTransport(inbound)(opts)
	}
}
