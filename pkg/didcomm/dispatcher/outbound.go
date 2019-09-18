/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// OutboundDispatcher dispatch msgs to destination
type OutboundDispatcher struct {
	outboundTransport []transport.OutboundTransport
}

// NewOutbound return new dispatcher outbound instance
func NewOutbound(outboundTransport []transport.OutboundTransport) *OutboundDispatcher {
	return &OutboundDispatcher{outboundTransport: outboundTransport}
}

// Send msg
func (o *OutboundDispatcher) Send(msg interface{}, des *Destination) error {
	// TODO add send logic
	return errors.New("not implemented")
}
