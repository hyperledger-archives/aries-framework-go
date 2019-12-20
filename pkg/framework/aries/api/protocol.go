/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/didconnection"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
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
	DIDConnectionStore() didconnection.Store
	Packager() transport.Packager
	InboundTransportEndpoint() string
	VDRIRegistry() vdriapi.Registry
	Signer() kms.Signer
	TransientStorageProvider() storage.Provider
}

// ProtocolSvcCreator method to create new protocol service
type ProtocolSvcCreator func(prv Provider) (dispatcher.Service, error)
