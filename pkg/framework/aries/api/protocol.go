/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"github.com/go-openapi/runtime/middleware/denco"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"golang.org/x/xerrors"
)

// SvcErrNotFound is returned when service not found
var SvcErrNotFound = xerrors.New("service not found")

//Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() denco.HandlerFunc
}

// Provider interface for protocol ctx
type Provider interface {
	OutboundTransport() transport.OutboundTransport
	Service(id string) (interface{}, error)
}

// ProtocolSvcCreator method to create new protocol service
type ProtocolSvcCreator func(prv Provider) (dispatcher.Service, error)
