// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go

require (
	github.com/VictoriaMetrics/fastcache v1.5.7
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v1.0.1
	github.com/go-kivik/couchdb v2.0.0+incompatible
	github.com/go-kivik/kivik v2.0.0+incompatible
	github.com/golang/mock v1.4.0
	github.com/golang/protobuf v1.3.3
	github.com/google/tink v1.4.0-rc2.0.20200525085439-8bdaed4f41ed
	github.com/google/tink/go v1.4.0-rc2.0.20200525085439-8bdaed4f41ed
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.3
	github.com/kr/pretty v0.1.0 // indirect
	github.com/minio/sha256-simd v0.1.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2
	github.com/multiformats/go-multibase v0.0.1
	github.com/multiformats/go-multihash v0.0.13
	github.com/piprate/json-gold v0.3.0
	github.com/rs/cors v1.7.0
	github.com/square/go-jose/v3 v3.0.0-20191119004800-96c717272387
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/goleveldb v1.0.0
	github.com/teserakt-io/golang-ed25519 v0.0.0-20200315192543-8255be791ce4
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.0.0-20200302210943-78000ba7a073
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980 // indirect
	golang.org/x/sys v0.0.0-20200202164722-d101bd2416d5 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v2 v2.2.8 // indirect
	nhooyr.io/websocket v1.8.3
)

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

go 1.14
