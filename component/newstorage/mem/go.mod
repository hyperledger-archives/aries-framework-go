// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/component/newstorage/mem

go 1.15

require (
	github.com/hyperledger/aries-framework-go v0.1.5
	github.com/hyperledger/aries-framework-go/component/newstorage v0.0.0
	github.com/hyperledger/aries-framework-go/test/newstorage v0.0.0
)

replace (
	github.com/hyperledger/aries-framework-go => ../../..
	github.com/hyperledger/aries-framework-go/component/newstorage => ../
	github.com/hyperledger/aries-framework-go/test/newstorage => ../../../test/newstorage
)
