// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go

require (
	github.com/VictoriaMetrics/fastcache v1.5.5
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d
	github.com/decred/dcrd/dcrec/secp256k1/v2 v2.0.0
	github.com/golang/mock v1.3.1
	github.com/google/tink v1.3.0-rc3
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.3
	github.com/multiformats/go-multibase v0.0.1
	github.com/multiformats/go-multihash v0.0.8
	github.com/piprate/json-gold v0.3.0
	github.com/square/go-jose/v3 v3.0.0-20190722231519-723929d55157
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/goleveldb v1.0.0
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.1.0
	golang.org/x/crypto v0.0.0-20191119213627-4f8c1d86b1ba
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980 // indirect
	golang.org/x/sys v0.0.0-20190616124812-15dcb6c0061f // indirect
	nhooyr.io/websocket v1.7.4
)

// Temporary workaround to support ES256K signature alg (until https://github.com/square/go-jose/pull/278 got merged)
replace github.com/square/go-jose/v3 v3.0.0-20190722231519-723929d55157 => github.com/kdimak/go-jose/v3 v3.0.0-20200110171146-c0aba788c306

go 1.13
