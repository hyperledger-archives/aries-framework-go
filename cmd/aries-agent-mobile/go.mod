// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile

go 1.16

require (
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210603210127-e57b8c94e3cf
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210820175050-dcc7a225178d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210820175050-dcc7a225178d
	github.com/hyperledger/aries-framework-go/test/component v0.0.0-20210820175050-dcc7a225178d
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/stretchr/testify v1.7.0
	nhooyr.io/websocket v1.8.3
)

replace (
	github.com/hyperledger/aries-framework-go => ../../
	github.com/hyperledger/aries-framework-go/component/storage/edv => ../../component/storage/edv // TODO (#2815) remove this once the wallet package doesn't import edv
	github.com/hyperledger/aries-framework-go/component/storageutil => ../../component/storageutil
	github.com/hyperledger/aries-framework-go/spi => ../../spi
)
