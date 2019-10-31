// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/test/bdd

go 1.13

require (
	github.com/DATA-DOG/godog v0.7.13
	github.com/fsouza/go-dockerclient v1.5.0
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go v0.0.0
	github.com/trustbloc/sidetree-core-go v0.1.0

)

replace github.com/hyperledger/aries-framework-go => ../..
