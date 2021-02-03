// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/component/newstorage/batchedstore

go 1.15

require (
	github.com/hyperledger/aries-framework-go v0.0.0
	github.com/hyperledger/aries-framework-go/component/newstorage/formattedstore v0.0.0
	github.com/hyperledger/aries-framework-go/component/newstorage/mock v0.0.0
	github.com/hyperledger/aries-framework-go/component/newstorage/mem v0.0.0
	github.com/hyperledger/aries-framework-go/test/newstorage v0.0.0
	github.com/stretchr/testify v1.6.1
)

replace (
	github.com/hyperledger/aries-framework-go => ../../..
	github.com/hyperledger/aries-framework-go/component/newstorage/formattedstore => ../formattedstore
	github.com/hyperledger/aries-framework-go/component/newstorage/mem => ../mem
	github.com/hyperledger/aries-framework-go/component/newstorage/mock => ../mock
	github.com/hyperledger/aries-framework-go/test/newstorage => ../../../test/newstorage
)
