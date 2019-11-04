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
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// ErrSvcNotFound is returned when service not found
var ErrSvcNotFound = errors.New("service not found")

// Provider interface for protocol ctx
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	KMS() kms.KeyManager
	Crypter() crypto.Crypter
	Packager() envelope.Packager
	InboundTransportEndpoint() string
	DIDCreator() didcreator.Creator
	Signer() kms.Signer
	DIDResolver() didresolver.Resolver
	DIDStore() didstore.Storage
	TransientStorageProvider() storage.Provider
}

// ProtocolSvcCreator method to create new protocol service
type ProtocolSvcCreator func(prv Provider) (dispatcher.Service, error)
