[![Release](https://img.shields.io/github/release/hyperledger/aries-framework-go.svg?style=flat-square)](https://github.com/hyperledger/aries-framework-go/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/aries-framework-go/master/LICENSE)

[![CircleCI](https://circleci.com/gh/hyperledger/aries-framework-go.svg?style=svg)](https://circleci.com/gh/hyperledger/aries-framework-go)
[![codecov](https://codecov.io/gh/hyperledger/aries-framework-go/branch/master/graph/badge.svg)](https://codecov.io/gh/hyperledger/aries-framework-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/hyperledger/aries-framework-go)](https://goreportcard.com/report/github.com/hyperledger/aries-framework-go)

# aries-framework-go

## Introduction
A Go framework for Aries

## Build
##### Prerequisites (General)
- Go 1.12

##### Prerequisites (for running tests)
- Go 1.12
- Docker
- Make

##### Targets
```
# run all the project build targets
make all

# run linter checks
make checks

# run unit tests
make unit-test
```

**Note: ** setting your `GOPROXY` is highly recommended to avoid the error `failed to load program with go/packages` during the build.

##### Crypto material generation for tests
For unit-tests, crypto material is generated under:

`pkg/didcomm/transport/http/testdata`

using the `openssl` tool. 

It is generated automatically when running unit tests. 

If you wish to regenerate it, you can delete this folder and:
1. run `make unit-test`
 or
2. cd into `pkg/didcomm/transport/http/` and run `go generate`

## Contributing

Found a bug? Ready to submit a PR? Want to submit a proposal for your grand
idea? Follow our [guidelines](.github/CONTRIBUTING.md) for more information
to get you started!

## License

Hyperledger Aries Framework Go is licensed under the [Apache License Version 2.0](LICENSE).
