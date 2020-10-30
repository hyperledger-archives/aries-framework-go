// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile

go 1.15

require (
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201017112511-5734c20820a9
	github.com/stretchr/testify v1.6.1
	nhooyr.io/websocket v1.8.3
)

replace (
	github.com/hyperledger/aries-framework-go => ../../
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201008080608-ba2e87ef05ef
	github.com/phoreproject/bls => github.com/trustbloc/bls v0.0.0-20201023141329-a1e218beb89e
)
