// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/test/bdd

go 1.16

require (
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/containerd/cgroups v0.0.0-20201119153540-4cbc285b3327 // indirect
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.7.3
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210603210127-e57b8c94e3cf
	github.com/hyperledger/aries-framework-go/component/storage/leveldb v0.0.0-20210603182844-353ecb34cf4d
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210708130136-17663938344d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210708130136-17663938344d
	github.com/onsi/ginkgo v1.10.1 // indirect
	github.com/onsi/gomega v1.7.0 // indirect
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/piprate/json-gold v0.4.0
	github.com/trustbloc/sidetree-core-go v0.6.0
	go.opencensus.io v0.22.5 // indirect
	nhooyr.io/websocket v1.8.3
)

replace (
	github.com/hyperledger/aries-framework-go => ../..
	github.com/hyperledger/aries-framework-go/component/storage/leveldb => ../../component/storage/leveldb
	github.com/hyperledger/aries-framework-go/component/storageutil => ../../component/storageutil
	github.com/hyperledger/aries-framework-go/spi => ../../spi
	github.com/hyperledger/aries-framework-go/test/component => ../../test/component
)
