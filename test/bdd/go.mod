// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/test/bdd

go 1.15

require (
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v1.0.1
	github.com/containerd/containerd v1.3.3 // indirect
	github.com/cucumber/godog v0.8.1
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/fsouza/go-dockerclient v1.6.1
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201017112511-5734c20820a9
	github.com/hyperledger/aries-framework-go/component/storage/leveldb v0.0.0-00010101000000-000000000000
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo v1.10.1 // indirect
	github.com/onsi/gomega v1.7.0 // indirect
	github.com/piprate/json-gold v0.3.0
	github.com/trustbloc/sidetree-core-go v0.1.5-0.20201006193409-11b061380f5b
	nhooyr.io/websocket v1.8.3
)

replace (
	github.com/hyperledger/aries-framework-go => ../..
	github.com/hyperledger/aries-framework-go/component/storage/leveldb => ../../component/storage/leveldb
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201008080608-ba2e87ef05ef
	github.com/phoreproject/bls => github.com/trustbloc/bls v0.0.0-20201008085849-81064514c3cc
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
)
