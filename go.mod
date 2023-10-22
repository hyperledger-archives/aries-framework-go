// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go

// TODO (#2815): Remove circular dependency between the main module and component/storage/edv

go 1.20

require (
	github.com/IBM/mathlib v0.0.3-0.20230605104224-932ab92f2ce0
	github.com/PaesslerAG/gval v1.1.0
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/go-jose/go-jose/v3 v3.0.1-0.20221117193127-916db76e8214
	github.com/golang/mock v1.4.4
	github.com/golang/protobuf v1.5.2
	github.com/google/tink/go v1.7.0
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go/component/didconfig v0.0.0-20230622211121-852ce35730b4
	github.com/hyperledger/aries-framework-go/component/kmscrypto v0.0.0-20230622082138-3ffab1691857
	github.com/hyperledger/aries-framework-go/component/log v0.0.0-20230427134832-0c9969493bd3
	github.com/hyperledger/aries-framework-go/component/models v0.0.0-20230622171716-43af8054a539
	github.com/hyperledger/aries-framework-go/component/storage/edv v0.0.0-20221025204933-b807371b6f1e
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20230427134832-0c9969493bd3
	github.com/hyperledger/aries-framework-go/component/vdr v0.0.0-20230622171716-43af8054a539
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20230517133327-301aa0597250
	github.com/hyperledger/ursa-wrapper-go v0.3.1
	github.com/mitchellh/mapstructure v1.5.0
	github.com/multiformats/go-multibase v0.1.1
	github.com/piprate/json-gold v0.5.1-0.20230111113000-6ddbe6e6f19f
	github.com/pkg/errors v0.9.1
	github.com/rs/cors v1.7.0
	github.com/stretchr/testify v1.8.1
	golang.org/x/crypto v0.1.0
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9
	nhooyr.io/websocket v1.8.3
)

require (
	github.com/VictoriaMetrics/fastcache v1.5.7 // indirect
	github.com/btcsuite/btcd v0.22.3 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.9.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20230602173724-9e02669dceb2 // indirect
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a // indirect
	github.com/kawamuray/jsonpath v0.0.0-20201211160320-7483bafabd7e // indirect
	github.com/kilic/bls12-381 v0.1.1-0.20210503002446-7b7597926c69 // indirect
	github.com/klauspost/compress v1.10.0 // indirect
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1 // indirect
	github.com/minio/sha256-simd v0.1.1 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/multiformats/go-multihash v0.0.13 // indirect
	github.com/multiformats/go-varint v0.0.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/tidwall/gjson v1.14.3 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.1.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	golang.org/x/time v0.1.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/hyperledger/aries-framework-go/component/models => ./component/models

replace github.com/hyperledger/aries-framework-go/component/kmscrypto => ./component/kmscrypto
