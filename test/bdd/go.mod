// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/test

go 1.13

require (
	github.com/DATA-DOG/godog v0.7.13
	github.com/fsouza/go-dockerclient v1.3.0
	github.com/go-openapi/swag v0.19.0
	github.com/hyperledger/aries-framework-go v0.0.0
	github.com/sirupsen/logrus v1.3.0
	github.com/trustbloc/sidetree-core-go v0.0.0-20190704193342-317707b882f9
	github.com/trustbloc/sidetree-node v0.0.0-20190715191925-1163ec4ac9ad

)

replace github.com/hyperledger/aries-framework-go => ../..
