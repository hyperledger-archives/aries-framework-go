// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/component/newstorage/mem

go 1.15

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hyperledger/aries-framework-go/component/newstorage v0.0.0-20210204181301-2bb923fb640d
	github.com/hyperledger/aries-framework-go/test/newstorage v0.0.0
	github.com/kr/pretty v0.1.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace github.com/hyperledger/aries-framework-go/test/newstorage => ../../../test/newstorage
