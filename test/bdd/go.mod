// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/test/bdd

go 1.16

require (
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/Microsoft/hcsshim v0.8.11 // indirect
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/containerd/cgroups v0.0.0-20201119153540-4cbc285b3327 // indirect
	github.com/containerd/containerd v1.4.3 // indirect
	github.com/containerd/continuity v0.0.0-20201208142359-180525291bb7 // indirect
	github.com/cucumber/godog v0.8.1
	github.com/docker/docker v20.10.0+incompatible // indirect
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210603210127-e57b8c94e3cf
	github.com/hyperledger/aries-framework-go/component/storage/leveldb v0.0.0-20210820175050-dcc7a225178d
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210820175050-dcc7a225178d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210820175050-dcc7a225178d
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/moby/term v0.0.0-20201110203204-bea5bbe245bf // indirect
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/trustbloc/sidetree-core-go v0.6.0
	go.opencensus.io v0.22.5 // indirect
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a // indirect
	nhooyr.io/websocket v1.8.3
)

replace (
	github.com/hyperledger/aries-framework-go => ../..
	github.com/hyperledger/aries-framework-go/component/storage/leveldb => ../../component/storage/leveldb
	github.com/hyperledger/aries-framework-go/component/storageutil => ../../component/storageutil
	github.com/hyperledger/aries-framework-go/spi => ../../spi
	github.com/hyperledger/aries-framework-go/test/component => ../../test/component
)
