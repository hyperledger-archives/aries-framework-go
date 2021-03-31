// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/test/bdd

go 1.16

require (
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/Microsoft/hcsshim v0.8.11 // indirect
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/containerd/cgroups v0.0.0-20201119153540-4cbc285b3327 // indirect
	github.com/containerd/containerd v1.4.3 // indirect
	github.com/containerd/continuity v0.0.0-20201208142359-180525291bb7 // indirect
	github.com/cucumber/godog v0.8.1
	github.com/docker/docker v20.10.0+incompatible // indirect
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210304193329-f56b2cebc386
	github.com/hyperledger/aries-framework-go/component/storage/leveldb v0.0.0-20210305152013-b276ca413681
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210320144851-40976de98ccf
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/moby/term v0.0.0-20201110203204-bea5bbe245bf // indirect
	github.com/piprate/json-gold v0.4.0
	github.com/trustbloc/sidetree-core-go v0.6.0
	go.opencensus.io v0.22.5 // indirect
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a // indirect
	golang.org/x/sys v0.0.0-20201214095126-aec9a390925b // indirect
	nhooyr.io/websocket v1.8.3
)

replace github.com/hyperledger/aries-framework-go => ../..
