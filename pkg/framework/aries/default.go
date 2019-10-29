/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto/jwe/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	didcommtrans "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didmethod/peer"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/factory/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didstore"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// TODO handle the test scenario better (make dbPath constant).
//nolint:gochecknoglobals
var (
	// DBPath Level DB Path.
	dbPath             = "/tmp/peerstore/"
	defaultInboundPort = ":8090"
)

// transportProviderFactory provides default Outbound Transport provider factory
func transportProviderFactory() api.TransportProviderFactory {
	return transport.NewProviderFactory()
}

// didResolverProvider provides default DID resolver.
func didResolverProvider(dbstore storage.Store) didresolver.Resolver {
	return didresolver.New(didresolver.WithDidMethod(peer.NewDIDResolver(peer.NewDIDStore(dbstore))))
}

func storeProvider() (storage.Provider, error) {
	storeProv, err := leveldb.NewProvider(dbPath)
	if err != nil {
		return nil, fmt.Errorf("leveldb provider initialization failed : %w", err)
	}
	return storeProv, nil
}

func inboundTransport() (didcommtrans.InboundTransport, error) {
	inbound, err := http.NewInbound(defaultInboundPort, "")
	if err != nil {
		return nil, fmt.Errorf("http inbound transport initialization failed: %w", err)
	}
	return inbound, nil
}

// defFrameworkOpts provides default framework options
func defFrameworkOpts(frameworkOpts *Aries) error {
	// TODO Move default providers to the sub-package #209
	// protocol provider factory
	if frameworkOpts.transport == nil {
		frameworkOpts.transport = transportProviderFactory()
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

	didDBStore, err := frameworkOpts.storeProvider.OpenStore(peer.StoreNamespace)
	if err != nil {
		return fmt.Errorf("storage initialization failed : %w", err)
	}

	if frameworkOpts.didResolver == nil {
		frameworkOpts.didResolver = didResolverProvider(didDBStore)
	}

	if frameworkOpts.didStore == nil {
		frameworkOpts.didStore = didstore.New(didstore.WithDidMethod(peer.NewDIDStore(didDBStore)))
	}

	newExchangeSvc := func(prv api.Provider) (dispatcher.Service, error) {
		dc, err := didcreator.New(prv,
			didcreator.WithDidMethod(peer.NewDIDCreator()),
			didcreator.WithCreatorServiceType("did-communication"),
			didcreator.WithCreatorServiceEndpoint(prv.InboundTransportEndpoint()))
		if err != nil {
			return nil, err
		}
		return didexchange.New(dc, prv)
	}
	frameworkOpts.protocolSvcCreators = append(frameworkOpts.protocolSvcCreators, newExchangeSvc)

	setAdditionalDefaultOpts(frameworkOpts)

	return nil
}

func setAdditionalDefaultOpts(frameworkOpts *Aries) {
	if frameworkOpts.walletCreator == nil {
		frameworkOpts.walletCreator = func(provider api.Provider) (api.CloseableWallet, error) {
			return wallet.New(provider)
		}
	}

	if frameworkOpts.crypterCreator == nil {
		frameworkOpts.crypterCreator = func(provider crypto.Provider) (crypto.Crypter, error) {
			return authcrypt.New(provider, authcrypt.XC20P)
		}
	}

	if frameworkOpts.packagerCreator == nil {
		frameworkOpts.packagerCreator = func(provider envelope.Provider) (envelope.Packager, error) {
			return envelope.New(provider)
		}
	}

	if frameworkOpts.outboundDispatcherCreator == nil {
		frameworkOpts.outboundDispatcherCreator = func(prv dispatcher.Provider) (dispatcher.Outbound, error) {
			return dispatcher.NewOutbound(prv), nil
		}
	}
}
