// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest

go 1.19

require (
	github.com/cenkalti/backoff/v4 v4.1.2
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go v0.1.9-0.20221021224215-368f53b380a4
	github.com/hyperledger/aries-framework-go/component/storage/leveldb v0.0.0-20220322085443-50e8f9bd208b
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20220322085443-50e8f9bd208b
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20221021224215-368f53b380a4
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.8.1
)

require (
	github.com/PaesslerAG/gval v1.1.0 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/VictoriaMetrics/fastcache v1.5.7 // indirect
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833 // indirect
	github.com/btcsuite/btcd v0.22.0-beta // indirect
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-kivik/couchdb/v3 v3.2.6 // indirect
	github.com/go-kivik/kivik/v3 v3.2.3 // indirect
	github.com/go-sql-driver/mysql v1.5.0 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/tink/go v1.7.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hyperledger/aries-framework-go/component/storage/edv v0.0.0-20221021224215-368f53b380a4 // indirect
	github.com/hyperledger/ursa-wrapper-go v0.3.1 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.8.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.0.6 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.7.0 // indirect
	github.com/jackc/pgx/v4 v4.11.0 // indirect
	github.com/jackc/puddle v1.1.3 // indirect
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a // indirect
	github.com/kawamuray/jsonpath v0.0.0-20201211160320-7483bafabd7e // indirect
	github.com/kilic/bls12-381 v0.1.1-0.20210503002446-7b7597926c69 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1 // indirect
	github.com/minio/sha256-simd v0.1.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.1.1 // indirect
	github.com/multiformats/go-multihash v0.0.13 // indirect
	github.com/multiformats/go-varint v0.0.5 // indirect
	github.com/onsi/ginkgo v1.10.1 // indirect
	github.com/onsi/gomega v1.7.0 // indirect
	github.com/piprate/json-gold v0.4.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693 // indirect
	github.com/syndtr/goleveldb v1.0.0 // indirect
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/tidwall/gjson v1.6.7 // indirect
	github.com/tidwall/match v1.0.3 // indirect
	github.com/tidwall/pretty v1.0.2 // indirect
	github.com/tidwall/sjson v1.1.4 // indirect
	github.com/valyala/fastjson v1.6.3 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.0.2 // indirect
	github.com/xdg-go/stringprep v1.0.2 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	go.mongodb.org/mongo-driver v1.8.0 // indirect
	golang.org/x/net v0.1.0 // indirect
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9 // indirect
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	nhooyr.io/websocket v1.8.3 // indirect
)

require (
	github.com/golang/snappy v0.0.4 // indirect
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20220629202442-ce8776c10037
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20220629202442-ce8776c10037
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20220629202442-ce8776c10037
	github.com/hyperledger/aries-framework-go-ext/component/storage/postgresql v0.0.0-20220629202442-ce8776c10037
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.1.0 // indirect
)

replace (
	github.com/hyperledger/aries-framework-go => ../..
	//	github.com/hyperledger/aries-framework-go/component/storage/edv => ../../component/storage/edv // TODO (#2815) remove this once the wallet package doesn't import edv
	github.com/hyperledger/aries-framework-go/component/storage/leveldb => ../../component/storage/leveldb
	github.com/hyperledger/aries-framework-go/component/storageutil => ../../component/storageutil
	github.com/hyperledger/aries-framework-go/spi => ../../spi
)
