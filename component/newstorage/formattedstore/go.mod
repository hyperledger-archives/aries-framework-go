// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/component/newstorage/formattedstore

go 1.15

require (
	github.com/google/tink/go v1.5.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210204185537-52da1315cbf0
	github.com/hyperledger/aries-framework-go/component/newstorage v0.0.0-20210204193554-c075603f3ac4
	github.com/hyperledger/aries-framework-go/component/newstorage/edv v0.0.0
	github.com/hyperledger/aries-framework-go/component/newstorage/mem v0.0.0
	github.com/hyperledger/aries-framework-go/component/newstorage/mock v0.0.0
	github.com/hyperledger/aries-framework-go/test/newstorage v0.0.0-20210204193554-c075603f3ac4
	github.com/stretchr/testify v1.6.1
)

replace (
	github.com/hyperledger/aries-framework-go/component/newstorage/edv => ../edv
	github.com/hyperledger/aries-framework-go/component/newstorage/mem => ../mem
	github.com/hyperledger/aries-framework-go/component/newstorage/mock => ../mock
)
