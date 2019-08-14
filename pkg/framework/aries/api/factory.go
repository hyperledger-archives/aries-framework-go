/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// TransportProviderFactory allows overriding of aries protocol providers
type TransportProviderFactory interface {
	CreateOutboundTransport() transport.OutboundTransport
}
