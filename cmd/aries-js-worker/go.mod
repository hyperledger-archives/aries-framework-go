// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-js-worker

go 1.16

require (
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210409151411-eeeb8508bd87
	github.com/hyperledger/aries-framework-go/component/storage/indexeddb v0.0.0-00010101000000-000000000000
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210409151411-eeeb8508bd87
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210412201938-efffe3eafcd1
	github.com/mitchellh/mapstructure v1.3.0
	github.com/stretchr/testify v1.7.0
)

replace (
	github.com/hyperledger/aries-framework-go => ../..
	github.com/hyperledger/aries-framework-go/component/storage/indexeddb => ../../component/storage/indexeddb
	github.com/hyperledger/aries-framework-go/component/storageutil => ../../component/storageutil
	github.com/hyperledger/aries-framework-go/spi => ../../spi
	github.com/hyperledger/aries-framework-go/test/component => ../../test/component
)
