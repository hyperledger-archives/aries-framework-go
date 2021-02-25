// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest

replace github.com/hyperledger/aries-framework-go => ../..

require (
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201017112511-5734c20820a9
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210224230531-58e1368e5661
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210224230531-58e1368e5661
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.7.0
)

go 1.15
