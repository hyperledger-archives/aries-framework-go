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
	github.com/flimzy/diff v0.1.7 // indirect
	github.com/flimzy/testy v0.1.17 // indirect
	github.com/go-kivik/couchdb v2.0.0+incompatible
	github.com/go-kivik/kivik v2.0.0+incompatible
	github.com/go-kivik/kiviktest v2.0.0+incompatible // indirect
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang/mock v1.4.0
	github.com/golang/protobuf v1.3.3
	github.com/google/tink/go v1.4.0-rc2.0.20200807212851-52ae9c6679b2
	github.com/google/uuid v1.1.1
	github.com/gopherjs/gopherjs v0.0.0-20200217142428-fce0ec30dd00 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/kr/pretty v0.1.0 // indirect
	github.com/minio/sha256-simd v0.1.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2
	github.com/multiformats/go-multibase v0.0.1
	github.com/multiformats/go-multihash v0.0.13
	github.com/piprate/json-gold v0.3.0
	github.com/pkg/errors v0.9.1
	github.com/rs/cors v1.7.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.6.1
	github.com/syndtr/goleveldb v1.0.0
	github.com/teserakt-io/golang-ed25519 v0.0.0-20200315192543-8255be791ce4
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonschema v1.2.0
	gitlab.com/flimzy/testy v0.2.1 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v2 v2.2.8 // indirect
	nhooyr.io/websocket v1.8.3
)

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

go 1.15
