// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest

replace github.com/hyperledger/aries-framework-go => ../..

require (
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/golang/snappy v0.0.3 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210304193329-f56b2cebc386
	github.com/hyperledger/aries-framework-go/component/storage/leveldb v0.0.0-20210305152013-b276ca413681
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210224230531-58e1368e5661
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210305152013-b276ca413681
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.7.0
)

go 1.15
