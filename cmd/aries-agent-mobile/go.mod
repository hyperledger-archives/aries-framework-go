// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile

go 1.15

require (
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201017112511-5734c20820a9
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210310001230-bc1bd8ea889c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210310001230-bc1bd8ea889c
	github.com/hyperledger/aries-framework-go/test/component v0.0.0-20210226235232-298aa129d822
	github.com/stretchr/testify v1.7.0
	nhooyr.io/websocket v1.8.3
)

replace github.com/hyperledger/aries-framework-go => ../../
