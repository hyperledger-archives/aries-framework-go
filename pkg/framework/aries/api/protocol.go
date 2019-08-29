/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"golang.org/x/xerrors"
)

// SvcErrNotFound is returned when service not found
var SvcErrNotFound = xerrors.New("service not found")

// Provider interface for protocol ctx
type Provider interface {
	OutboundTransport() transport.OutboundTransport
	Service(id string) (interface{}, error)
	ProtocolConfig() ProtocolConfig
}

// ProtocolSvcCreator method to create new protocol service
type ProtocolSvcCreator func(prv Provider) (dispatcher.Service, error)
