[![Release](https://img.shields.io/github/release/hyperledger/aries-framework-go.svg?style=flat-square)](https://github.com/hyperledger/aries-framework-go/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/hyperledger/aries-framework-go/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/hyperledger/aries-framework-go)

[![Build Status](https://github.com/hyperledger/aries-framework-go/workflows/build/badge.svg)](https://github.com/hyperledger/aries-framework-go/actions)
[![codecov](https://codecov.io/gh/hyperledger/aries-framework-go/branch/main/graph/badge.svg)](https://codecov.io/gh/hyperledger/aries-framework-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/hyperledger/aries-framework-go)](https://goreportcard.com/report/github.com/hyperledger/aries-framework-go)

# <p><img src="https://raw.githubusercontent.com/hyperledger/aries-rfcs/1371a4807ead74c36ea7d5af909064ec491b78c1/collateral/Hyperledger_Aries_Logo_Color.png" height="50px" alt="Hyperledger Aries">Framework Go</p>

Hyperledger Aries Framework Go enables trusted communication and data exchange based on interoperable distributed ledger technologies (DLTs) and peer-to-peer (P2P) interactions.
We provide a flexible toolkit to enable the usage of decentralized identifiers (DIDs), DID-to-DID communications, verifiable credential exchange, transaction authorizations, and data communication protocols. From these building blocks, implementors can build agents, mediators and other DIDComm features in a manner that is agnostic to a particular DID network or governance framework.

We aim to provide Go implementations of:

- Decentralized identity standards including [W3C decentralized identifiers](https://w3c.github.io/did-core/) (DIDs), [W3C DID resolution](https://w3c-ccg.github.io/did-resolution/), and [W3C verifiable credentials](https://w3c.github.io/vc-data-model/).
- Decentralized data communication protocols anchored in DIDs: [DIDComm](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0005-didcomm).
- A pluggable dependency framework, where implementors can customize primitives via Service Provider Interfaces (SPIs). We have a "batteries included" model where default primitives are included -- such as a [key management system (KMS)](docs/kms_secretlock.md), crypto, data storage, encrypted data vault integration, etc.

We aim to enable usage of our protocol implementations in a wide variety of edge and cloud environments including servers, browsers, mobile, and devices.
API bindings are supplied to enable these environments including:

- Go
- REST
- JavaScript / WebAssembly
- Android
- iOS
- C (future)

We implement demonstrations and test cases, that require a ledger system, using [DIF Sidetree protocol](https://github.com/decentralized-identity/sidetree/blob/master/docs/protocol.md) as this protocol enables generic decentralized ledger systems to operate as a DID network.

## Documentation
Aries Framework Go documentation can be viewed at [GoDoc](https://pkg.go.dev/github.com/hyperledger/aries-framework-go). The project structure is described [here](docs/project_structure.md).

The project structure for the mobile bindings can be found [here](cmd/aries-agent-mobile/doc/project_structure.md).

The packages intended for end developer usage are within the [pkg/client](https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/client) folder along with the main agent package ([pkg/framework/aries](https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/framework/aries)).

The project can also be used as a [DIDComm Router/Mediator](docs/didcomm_mediator.md).

Information about Verifiable Credential Wallet framework based on [Universal Wallet](https://w3c-ccg.github.io/universal-wallet-interop-spec/) can be found [here](docs/vc_wallet.md).

Key concepts about the Hyperledger Aries Project can be found [here](/docs/concepts).

Details of the standards followed and specifications implemented by Hyperledger Aries Project can be found [here](docs/concepts/02_standards.md).

## Controller Bindings
- [Go](docs/go/README.md)
- [REST](docs/rest/README.md)
  - [Run OpenAPI Demo](docs/rest/openapi_demo.md)
  - Get the Docker image from [GitHub Packages](https://github.com/hyperledger/aries-framework-go/packages/69982)
- [JavaScript](cmd/aries-js-worker/README.md)
  - Get it from [GitHub Packages](https://github.com/hyperledger/aries-framework-go/packages/123279)
- [Mobile](cmd/aries-agent-mobile/README.md)

## Testing
- [Build](docs/test/build.md)
- [BDD tests](docs/test/bdd_tests.md)

## Contributing
Found a bug? Ready to submit a PR? Want to submit a proposal for your grand
idea? Follow our [guidelines](.github/CONTRIBUTING.md) for more information
to get you started!

## License
Hyperledger Aries Framework Go is licensed under the [Apache License Version 2.0 (Apache-2.0)](LICENSE).

Hyperledger Aries Framework Go [documentation](docs) is licensed under the [Creative Commons Attribution 4.0 International License (CC-BY-4.0)](http://creativecommons.org/licenses/by/4.0/).
