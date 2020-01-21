/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// ErrSvcNotFound is returned when service not found
var ErrSvcNotFound = errors.New("service not found")

// Provider interface for protocol ctx
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	Messenger() service.Messenger
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	LegacyKMS() legacykms.KeyManager
	Crypto() crypto.Crypto
	Packager() transport.Packager
	InboundTransportEndpoint() string
	VDRIRegistry() vdriapi.Registry
	Signer() legacykms.Signer
	TransientStorageProvider() storage.Provider
}

// ProtocolSvcCreator method to create new protocol service
type ProtocolSvcCreator func(prv Provider) (dispatcher.ProtocolService, error)

// MessageServiceProvider is provider of message services
type MessageServiceProvider interface {
	// Services returns list of available message services in this message handler
	Services() []dispatcher.MessageService
}
