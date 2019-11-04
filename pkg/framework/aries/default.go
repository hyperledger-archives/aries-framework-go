/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	didcommtrans "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didmethod/peer"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didstore"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

// TODO handle the test scenario better (make dbPath constant).
//nolint:gochecknoglobals
var (
	// DBPath Level DB Path.
	dbPath             = "/tmp/peerstore/"
	defaultInboundPort = ":8090"
)

func storeProvider() (storage.Provider, error) {
	storeProv, err := leveldb.NewProvider(dbPath)
	if err != nil {
		return nil, fmt.Errorf("leveldb provider initialization failed : %w", err)
	}

	return storeProv, nil
}

func inboundTransport() (didcommtrans.InboundTransport, error) {
	inbound, err := arieshttp.NewInbound(defaultInboundPort, "")
	if err != nil {
		return nil, fmt.Errorf("http inbound transport initialization failed: %w", err)
	}

	return inbound, nil
}

// defFrameworkOpts provides default framework options
func defFrameworkOpts(frameworkOpts *Aries) error {
	// TODO Move default providers to the sub-package #209
	if frameworkOpts.outboundTransport == nil {
		outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
		if err != nil {
			return fmt.Errorf("http outbound transport initialization failed: %w", err)
		}

		frameworkOpts.outboundTransport = outbound
	}

	if frameworkOpts.storeProvider == nil {
		storeProv, err := storeProvider()
		if err != nil {
			return fmt.Errorf("resolver initialization failed : %w", err)
		}

		frameworkOpts.storeProvider = storeProv
	}

	if frameworkOpts.inboundTransport == nil {
		inbound, err := inboundTransport()
		if err != nil {
			return fmt.Errorf("http inbound transport initialization failed: %w", err)
		}

		frameworkOpts.inboundTransport = inbound
	}

	peerDidStore, err := peer.NewDIDStore(frameworkOpts.storeProvider)
	if err != nil {
		return fmt.Errorf("failed to create new did store : %w", err)
	}

	if frameworkOpts.didResolver == nil {
		frameworkOpts.didResolver = didresolver.New(didresolver.WithDidMethod(peer.NewDIDResolver(peerDidStore)))
	}

	if frameworkOpts.didStore == nil {
		frameworkOpts.didStore = didstore.New(didstore.WithDidMethod(peerDidStore))
	}

	frameworkOpts.protocolSvcCreators = append(frameworkOpts.protocolSvcCreators, newExchangeSvc())

	setAdditionalDefaultOpts(frameworkOpts)

	return nil
}

func newExchangeSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.Service, error) {
		dc, err := didcreator.New(prv,
			didcreator.WithDidMethod(peer.NewDIDCreator()),
			didcreator.WithCreatorServiceType("did-communication"),
			didcreator.WithCreatorServiceEndpoint(prv.InboundTransportEndpoint()))
		if err != nil {
			return nil, err
		}

		return didexchange.New(dc, prv)
	}
}

func setAdditionalDefaultOpts(frameworkOpts *Aries) {
	if frameworkOpts.kmsCreator == nil {
		frameworkOpts.kmsCreator = func(provider api.Provider) (api.CloseableKMS, error) {
			return kms.New(provider)
		}
	}

	if frameworkOpts.packerCreator == nil {
		frameworkOpts.packerCreator = func(provider envelope.KMSProvider) (envelope.Packer, error) {
			return authcrypt.New(provider), nil
		}
	}

	if frameworkOpts.packagerCreator == nil {
		frameworkOpts.packagerCreator = func(provider envelope.PackerProvider) (envelope.Packager, error) {
			return envelope.New(provider)
		}
	}

	if frameworkOpts.outboundDispatcherCreator == nil {
		frameworkOpts.outboundDispatcherCreator = func(prv dispatcher.Provider) (dispatcher.Outbound, error) {
			return dispatcher.NewOutbound(prv), nil
		}
	}

	if frameworkOpts.transientStoreProvider == nil {
		frameworkOpts.transientStoreProvider = mem.NewProvider()
	}
}
