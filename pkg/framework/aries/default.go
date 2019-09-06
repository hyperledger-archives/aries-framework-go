/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didmethod/peer"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/factory/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
)

// DBPath Level DB Path.
var dbPath = "/tmp/peerstore/"

// transportProviderFactory provides default Outbound Transport provider factory
func transportProviderFactory() api.TransportProviderFactory {
	return transport.NewProviderFactory()
}

// didResolverProvider provides default DID resolver.
func didResolverProvider(dbprov storage.Provider) (DIDResolver, error) {
	dbstore, err := dbprov.GetStoreHandle()
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
	store, err := frameworkOpts.storeProvider.GetStoreHandle()
	if err != nil {
		return fmt.Errorf("get store handle failed : %w", err)
	}

	if frameworkOpts.didResolver == nil {
		reslv, err := didResolverProvider(frameworkOpts.storeProvider)
		if err != nil {
			return fmt.Errorf("resolver initialization failed : %w", err)
		}
		frameworkOpts.didResolver = reslv
	}

	newExchangeSvc := func(prv api.Provider) (dispatcher.Service, error) { return didexchange.New(store, prv), nil }
	frameworkOpts.protocolSvcCreators = append(frameworkOpts.protocolSvcCreators, newExchangeSvc)

	return nil
}
