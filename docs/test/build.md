# Aries Framework Go - Build

## Prerequisites (General)
- Go 1.16

## Prerequisites (for running tests and demos)
- Go 1.16
- Docker
- Docker-Compose
- Make
- bash
- Node.js (note: installation via [nvm](https://github.com/nvm-sh/nvm) is *recommended* to avoid errors due to local
  path permissions when running certain `npm` commands (eg. `npm link`). Otherwise, assign the proper permissions to the
  user account running `npm`)

## Targets
```
# run all the project build targets
make all

# run linter checks
make checks

# run unit tests
make unit-test

# run unit tests for wasm
# requires chrome to be installed
make unit-test-wasm

# run bdd tests
make bdd-test
```

## Crypto material generation for tests
For unit-tests, crypto material is generated under `pkg/didcomm/transport/http/testdata` folder using the `openssl` tool. 

If you wish to regenerate it, you can delete test data folder and:
1. run `make unit-test`
 or
2. cd into `pkg/didcomm/transport/http/` and run `go generate`

## Verifiable Credential Test Suite	
Install Node.js and mocha prior to running the test suite.

To test compatibility of the verifiable credential packages with 	
[W3C Verifiable Claims Working Group Test Suite](https://github.com/w3c/vc-test-suite), run `make vc-test-suite`.	
The result of the test suite is generated as `vc-test-suite/suite/implementations/aries-framework-go-report.json`.	
