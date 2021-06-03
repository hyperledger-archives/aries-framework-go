// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile

go 1.16

require (
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210603182844-353ecb34cf4d
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210603182844-353ecb34cf4d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210603182844-353ecb34cf4d
	github.com/hyperledger/aries-framework-go/test/component v0.0.0-20210603182844-353ecb34cf4d
	github.com/stretchr/testify v1.7.0
	nhooyr.io/websocket v1.8.3
)

replace (
	github.com/hyperledger/aries-framework-go => ../../
	github.com/hyperledger/aries-framework-go/component/storage/edv => ../../component/storage/edv // TODO (#2815) remove this once the wallet package doesn't import edv
	github.com/hyperledger/aries-framework-go/component/storageutil => ../../component/storageutil
	github.com/hyperledger/aries-framework-go/spi => ../../spi
	github.com/hyperledger/aries-framework-go/test/component => ../../test/component
)
