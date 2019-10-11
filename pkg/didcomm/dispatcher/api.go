/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// Service protocol service
type Service interface {
	service.Handler
	Accept(msgType string) bool
	Name() string
}

// Outbound interface
type Outbound interface {
	Send(interface{}, string, *service.Destination) error
}

// Provider interface for outbound ctx
type Provider interface {
	Packager() envelope.Packager
	OutboundTransports() []transport.OutboundTransport
}

// OutboundCreator method to create new outbound dispatcher service
type OutboundCreator func(prov Provider) (Outbound, error)
