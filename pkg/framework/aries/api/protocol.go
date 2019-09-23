/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// ErrSvcNotFound is returned when service not found
var ErrSvcNotFound = errors.New("service not found")

// Provider interface for protocol ctx
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	Service(id string) (interface{}, error)
	CryptoWallet() wallet.Crypto
	InboundTransportEndpoint() string
	DIDWallet() wallet.DIDCreator
}

// ProtocolSvcCreator method to create new protocol service
type ProtocolSvcCreator func(prv Provider) (dispatcher.Service, error)
