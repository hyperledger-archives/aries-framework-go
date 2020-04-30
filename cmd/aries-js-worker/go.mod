// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-js-worker

go 1.13

require (
	github.com/google/uuid v1.1.1
	github.com/hyperledger/aries-framework-go v0.0.0
	github.com/mitchellh/mapstructure v1.3.0
	github.com/stretchr/testify v1.5.1
)

replace github.com/hyperledger/aries-framework-go => ../../

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
