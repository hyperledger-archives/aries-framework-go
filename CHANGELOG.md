# 0.2.0

## Apr 5, 2023

- Presentation Exchange improvements
- SD-JWT documentation
- CI : Ubuntu runner update to v22.04

Refer https://github.com/hyperledger/aries-framework-go/releases/tag/v0.2.0 for new commits.

# 0.1.9

## Feb 24, 2023

Refer https://github.com/hyperledger/aries-framework-go/releases/tag/v0.1.9 for new commits.


# 0.1.8

## March 29, 2022

- DIDCommV2 full support:
  - Updated to V2 message structure
  - OOB V2
  - Issue Credential V3, Present Proof V3
  - Mediator protocol support for DIDComm V2
  - DID Rotation
- Universal Wallet:
  - WACI Issuance
  - WACI Presentation
  - Credential Manifest support & minor improvements
- Aries RFCs / Interop
  - Web-redirect support in issue-credential and present-proof protocols (V2 and V3)
  - Media type profile support
  - Various minor fixes
- Fixes and improvements to Crypto, KMS, VDR, Verifiable Credential, Storage, and other components

# 0.1.7

## September 14, 2021

- DIDCommV2 support for packing/unpacking
- DIDComm service block now uses KeyAgreement.ID for DIDCommV2 and did:key for DIDCommV1
- DID Connection store uses keyAgreement.ID for DIDCommV2 and did:key for DIDCommV1
- Present Proof V3
- Aries Framework Go wallet
- JSON-LD Context API
- Added a method to the storage iterator interface for getting total items
- Added sort order query options that can be supported by storage implementations
- Improved documentation for expected behaviours of various storage interface methods
- New common storage tests that check for more scenarios and improve consistency among implementations

# 0.1.6

## March 6, 2021

- RFC 0510: Presentation-Exchange Attachment (https://github.com/hyperledger/aries-framework-go/pull/2472)
- Presentation Exchange support (https://github.com/hyperledger/aries-framework-go/pull/2437)
- Present Proof supports BBS+ (https://github.com/hyperledger/aries-framework-go/pull/2602)
- Sign credential API - support BBS+ (https://github.com/hyperledger/aries-framework-go/pull/2601)
- Support BBS+ in KMS (https://github.com/hyperledger/aries-framework-go/issues/2295)
- Support name prefixes in localkms storage to create multi-tenant KMS (https://github.com/hyperledger/aries-framework-go/issues/2435)
- Created Service Provider Interface (SPI) module (https://github.com/hyperledger/aries-framework-go/pull/2512).
- Reworked storage interface to be more fully featured and to fit better with encrypted storage solutions like EDV.
- Added storage provider wrappers that can be used to add automatic caching and batching support to any concrete storage implementation.
- Added a common storage test suite for ensuring consistency across storage implementations.
- Various bug fixes and performance enhancements.

# 0.1.5

## December 7, 2020

- Support for encrypted storage capabilities (https://github.com/hyperledger/aries-framework-go/issues/2199).
- Support for capabilityChain in LD proofs (https://github.com/hyperledger/aries-framework-go/pull/2285).
- Support for BBS+ signatures 2020 (https://github.com/hyperledger/aries-framework-go/issues/1725).
- Support for `did:web` (https://github.com/hyperledger/aries-framework-go/issues/2288).
- Support for RemoteKMS and a WebKMS client.
- Support for Wrap and Unwrap in KMS.
