/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

// WithInboundHTTPAddr return new default http inbound transport.
func WithInboundHTTPAddr(internalAddr, externalAddr string) aries.Option {
	return func(opts *aries.Aries) error {
		inbound, err := http.NewInbound(internalAddr, externalAddr)
		if err != nil {
			return fmt.Errorf("http inbound transport initialization failed : %w", err)
		}
		return aries.WithInboundTransport(inbound)(opts)
	}
}

// WithInboundWSAddr return new default ws inbound transport.
func WithInboundWSAddr(internalAddr, externalAddr string) aries.Option {
	return func(opts *aries.Aries) error {
		inbound, err := ws.NewInbound(internalAddr, externalAddr)
		if err != nil {
			return fmt.Errorf("ws inbound transport initialization failed : %w", err)
		}
		return aries.WithInboundTransport(inbound)(opts)
	}
}
