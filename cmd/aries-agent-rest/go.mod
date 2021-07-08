// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest

go 1.16

require (
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/golang/snappy v0.0.3 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210603210127-e57b8c94e3cf
	github.com/hyperledger/aries-framework-go/component/storage/leveldb v0.0.0-20210603182844-353ecb34cf4d
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210708130136-17663938344d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210708130136-17663938344d
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.7.0
)

replace (
	github.com/hyperledger/aries-framework-go => ../..
	github.com/hyperledger/aries-framework-go/component/storage/edv => ../../component/storage/edv // TODO (#2815) remove this once the wallet package doesn't import edv
	github.com/hyperledger/aries-framework-go/component/storage/leveldb => ../../component/storage/leveldb
	github.com/hyperledger/aries-framework-go/component/storageutil => ../../component/storageutil
	github.com/hyperledger/aries-framework-go/spi => ../../spi
	github.com/hyperledger/aries-framework-go/test/component => ../../test/component
)
