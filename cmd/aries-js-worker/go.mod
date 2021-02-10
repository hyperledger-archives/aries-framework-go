// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/cmd/aries-js-worker

go 1.15

require (
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210209165120-79220075f539
	github.com/hyperledger/aries-framework-go/component/storage/jsindexeddb v0.0.0-00010101000000-000000000000
	github.com/mitchellh/mapstructure v1.3.0
	github.com/stretchr/testify v1.6.1
)

replace (
	github.com/hyperledger/aries-framework-go => ../../
	github.com/hyperledger/aries-framework-go/component/storage/indexeddb => ../../component/storage/indexeddb
	github.com/hyperledger/aries-framework-go/component/storage/jsindexeddb => ../../component/storage/jsindexeddb
)
