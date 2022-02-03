/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defaults

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

// WithInboundHTTPAddr return new default http inbound transport.
func WithInboundHTTPAddr(internalAddr, externalAddr, certFile, keyFile string) aries.Option {
	return func(opts *aries.Aries) error {
		inbound, err := http.NewInbound(internalAddr, externalAddr, certFile, keyFile)
		if err != nil {
			return fmt.Errorf("http inbound transport initialization failed : %w", err)
		}

		return aries.WithInboundTransport(inbound)(opts)
	}
}

// WithInboundWSAddr return new default ws inbound transport. If readLimit is 0, the default value of 32kB is set.
func WithInboundWSAddr(internalAddr, externalAddr, certFile, keyFile string, readLimit int64) aries.Option {
	return func(opts *aries.Aries) error {
		var inboundOpts []ws.InboundOpt

		if readLimit > 0 {
			inboundOpts = append(inboundOpts, ws.WithInboundReadLimit(readLimit))
		}

		inbound, err := ws.NewInbound(internalAddr, externalAddr, certFile, keyFile, inboundOpts...)
		if err != nil {
			return fmt.Errorf("ws inbound transport initialization failed : %w", err)
		}

		return aries.WithInboundTransport(inbound)(opts)
	}
}
