/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/common/did"
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
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
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
func didResolverProvider(dbprov storage.Provider) (didresolver.Resolver, error) {
	dbstore, err := dbprov.OpenStore(peer.StoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("storage initialization failed : %w", err)
	}

	resl := didresolver.New(didresolver.WithDidMethod(peer.NewDIDResolver(peer.NewDIDStore(dbstore))))
	return resl, nil
}

func storeProvider() (storage.Provider, error) {
	storeProv, err := leveldb.NewProvider(dbPath)
	if err != nil {
		return nil, fmt.Errorf("leveldb provider initialization failed : %w", err)
	}
	return storeProv, nil
}

func inboundTransport() (didcommtrans.InboundTransport, error) {
	inbound, err := http.NewInbound(defaultInboundPort)
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

	if frameworkOpts.didResolver == nil {
		resolver, err := didResolverProvider(frameworkOpts.storeProvider)
		if err != nil {
			return fmt.Errorf("resolver initialization failed : %w", err)
		}
		frameworkOpts.didResolver = resolver
	}

	setAdditionalDefaultOpts(frameworkOpts)

	newExchangeSvc := func(prv api.Provider) (dispatcher.Service, error) {
		return didexchange.New(did.NewPeerDIDCreator(prv), prv)
	}
	frameworkOpts.protocolSvcCreators = append(frameworkOpts.protocolSvcCreators, newExchangeSvc)

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
