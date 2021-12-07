/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// ErrSvcNotFound is returned when service not found.
var ErrSvcNotFound = errors.New("service not found")

// Provider interface for protocol ctx.
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	InboundDIDCommMessageHandler() func() service.InboundHandler
	Messenger() service.Messenger
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	KMS() kms.KeyManager
	SecretLock() secretlock.Service
	Crypto() crypto.Crypto
	Packager() transport.Packager
	ServiceEndpoint() string
	RouterEndpoint() string
	VDRegistry() vdrapi.Registry
	ProtocolStateStorageProvider() storage.Provider
	InboundMessageHandler() transport.InboundMessageHandler
	VerifiableStore() verifiable.Store
	DIDConnectionStore() did.ConnectionStore
	JSONLDDocumentLoader() ld.DocumentLoader
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
	AriesFrameworkID() string
	ServiceMsgTypeTargets() []dispatcher.MessageTypeTarget
}

// ProtocolSvcCreator struct sets initialization functions for a protocol service.
type ProtocolSvcCreator struct {
	// Create creates new protocol service.
	Create func(prv Provider) (dispatcher.ProtocolService, error)
	// Init initializes given instance of a protocol service.
	Init           func(svc dispatcher.ProtocolService, prv Provider) error
	ServicePointer dispatcher.ProtocolService
}

// MessageServiceProvider is provider of message services.
type MessageServiceProvider interface {
	// Services returns list of available message services in this message handler
	Services() []dispatcher.MessageService
}
