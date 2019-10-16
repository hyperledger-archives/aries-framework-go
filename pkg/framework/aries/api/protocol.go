/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// ErrSvcNotFound is returned when service not found
var ErrSvcNotFound = errors.New("service not found")

// Provider interface for protocol ctx
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	CryptoWallet() wallet.Crypto
	Crypter() crypto.Crypter
	Packager() envelope.Packager
	InboundTransportEndpoint() string
	DIDWallet() wallet.DIDCreator
	Signer() wallet.Signer
	DIDResolver() didresolver.Resolver
}

// ProtocolSvcCreator method to create new protocol service
type ProtocolSvcCreator func(prv Provider) (dispatcher.Service, error)
