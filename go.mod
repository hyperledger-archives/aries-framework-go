// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go

require (
	github.com/PaesslerAG/gval v1.0.0
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/VictoriaMetrics/fastcache v1.5.7
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v1.0.1
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/golang/mock v1.4.4
	github.com/golang/protobuf v1.4.2
	github.com/google/tink/go v1.5.0
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/kilic/bls12-381 v0.0.0-20200820230200-6b2c19996391
	github.com/minio/sha256-simd v0.1.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2
	github.com/multiformats/go-multibase v0.0.1
	github.com/multiformats/go-multihash v0.0.13
	github.com/piprate/json-gold v0.3.0
	github.com/pkg/errors v0.9.1
	github.com/rs/cors v1.7.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.6.1
	github.com/teserakt-io/golang-ed25519 v0.0.0-20200315192543-8255be791ce4
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/sys v0.0.0-20201009025420-dfb3f7c4e634 // indirect
	nhooyr.io/websocket v1.8.3
)

replace (
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
	github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
)

go 1.15
