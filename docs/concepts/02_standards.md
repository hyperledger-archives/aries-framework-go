# Standards and Specifications

Aries Framework Go is following many open source standards and specifications from,

- [Hyperledger Aries RFCs](https://github.com/hyperledger/aries-rfcs)
- [Decentralized Identity Foundation](https://identity.foundation/)
- [W3C](https://www.w3.org/)


### Decentralized Identity Foundation Standards

Aries Framework Go is following many standards from Decentralized Identity Foundation eco system for credential interactions.

Notable ones are,
* [DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/): Version 2.0 od DIDComm Messaging to provide a secure, private communication methodology built atop the decentralized design of DIDs.  
* [Presentation Exchange v2.0.0](https://identity.foundation/presentation-exchange/): An advanced form of credential request standard which codifies a data format Verifiers can use to articulate proof requirements, and a data format Holders can use to describe proofs submitted in accordance with them.
Mainly used in [Present Proof Protocol](00_what_is_hl_aries.md#8-presentproof-protocol) and [Aries Verifiable Credential Wallet](../vc_wallet.md) implementation.
* [Confidential Storage v0.1](https://identity.foundation/confidential-storage/): For secured storage implementation, also know as Encrypted Data Vault. 
* [WACI Presentation Exchange](https://identity.foundation/waci-presentation-exchange/): Wallet and credential interaction standards using DIDComm.
* [Credential Manifest](https://identity.foundation/credential-manifest/): Credential Manifests are a resource format that defines preconditional requirements, Issuer style preferences, Credential Style preferences and other facets User Agents utilize to help articulate and select the inputs necessary for processing and issuance of a specified credential.

### W3C Standards

Notable ones are,
 * [Universal Wallet 2020](https://w3c-ccg.github.io/universal-wallet-interop-spec/): Implemented as [Aries Verifiable Credential Wallet](../vc_wallet.md) implementation. 
 * [WACI Presentation Exchange](https://identity.foundation/waci-presentation-exchange/): Wallet and credential interaction standards 
 using DIDComm in [Present Proof Protocol](00_what_is_hl_aries.md#8-presentproof-protocol), [Issue Credential Protocol](00_what_is_hl_aries.md#3-issuecredential-protocol) and [Aries Verifiable Credential Wallet](../vc_wallet.md).
 * [Verifiable Presentation Request Specification v0.1](https://w3c-ccg.github.io/vp-request-spec/): Standards for requesting credentials to share from wallet. Used in [Aries Verifiable Credential Wallet](../vc_wallet.md) implementation.
 * [Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/): For all the verifiable credential data model operations. We support both JSON-LD and JWT verifiable credentials.
 * [JSON-LD v1.1](https://w3c.github.io/json-ld-syntax/): For JSON-based Serialization for Linked Data.
 * [Verifiable Credential Data Integrity 1.0](https://w3c.github.io/vc-data-integrity/): For generating JSON-LD based linked data proofs.
 * [Decentralized Identifiers (DIDs) v1.0](https://w3c.github.io/did-core/): For signing and verifying verifiable credentials and presentations.
 * [WebKMS v0.7](https://w3c-ccg.github.io/webkms/): For implementing cryptographic key management systems for the wallet.
 * [Decentralized Identifier Resolution (DID Resolution) v0.2](https://w3c-ccg.github.io/did-resolution/): Followed for resolving various decentralized identifiers. 


### Aries-RFCS

List of the notable aries-rfcs implemented by Aries Framework Go,
* [0348: Transition Message Type to HTTPs](https://github.com/hyperledger/aries-rfcs/blob/main/https://github.com/hyperledger/aries-rfcs/blob/main/features/0348-transition-msg-type-to-https/README.md)
* [0003: Protocols](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0003-protocols/README.md) 
* [0004: Agents](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0004-agents/README.md)
* [0005: DID Communication](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0005-didcomm/README.md)
* [0008: Message ID and Threading](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0008-message-id-and-threading/README.md) 
* [0011: Decorators](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0011-decorators/README.md) 
* [0015: ACKs](https://github.com/hyperledger/aries-rfcs/blob/main/features/0015-acks/README.md) 
* [0017: Attachments](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0017-attachments/README.md) 
* [0019: Encryption Envelope](https://github.com/hyperledger/aries-rfcs/blob/main/features/0019-encryption-envelope/README.md) 
* [0020: Message Types](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0020-message-types/README.md) 
* [0023: DID Exchange Protocol 1.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0023-did-exchange/README.md) 
* [0025: DIDComm Transports](https://github.com/hyperledger/aries-rfcs/blob/main/features/0025-didcomm-transports/README.md) 
* [0035: Report Problem Protocol 1.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md) 
* [0036: Issue Credential Protocol 1.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0036-issue-credential/README.md) 
* [0037: Present Proof Protocol 1.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0037-present-proof/README.md) 
* [0044: DIDComm File and MIME Types](https://github.com/hyperledger/aries-rfcs/blob/main/features/0044-didcomm-file-and-mime-types/README.md) 
* [0046: Mediators and Relays](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0046-mediators-and-relays/README.md) 
* [0047: JSON-LD Compatibility](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0047-json-ld-compatibility/README.md) 
* [0092: Transports Return Route](https://github.com/hyperledger/aries-rfcs/blob/main/features/0092-transport-return-route/README.md) 
* [0094: Cross-Domain Messaging](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0094-cross-domain-messaging/README.md) 
* [0095: Basic Message Protocol 1.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0095-basic-message/README.md) 
* [0160: Connection Protocol](https://github.com/hyperledger/aries-rfcs/blob/main/features/0160-connection-protocol/README.md) 
* [0211: Mediator Coordination Protocol](https://github.com/hyperledger/aries-rfcs/blob/main/features/0211-route-coordination/README.md) 
* [0302: Aries Interop Profile](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0302-aries-interop-profile/README.md) 
* [0360: did:key Usage](https://github.com/hyperledger/aries-rfcs/blob/main/features/0360-use-did-key/README.md) 
* [0434: Out-of-Band Protocol 1.1](https://github.com/hyperledger/aries-rfcs/blob/main/features/0434-outofband/README.md) 
* [0453: Issue Credential Protocol 2.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md) 
* [0454: Present Proof Protocol 2.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0454-present-proof-v2/README.md) 
* [0510: Presentation-Exchange Attachment format for requesting and presenting proofs](https://github.com/hyperledger/aries-rfcs/blob/main/features/0510-dif-pres-exch-attach/README.md) 
* [0519: Goal Codes](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0519-goal-codes/README.md) 
* [0587: Encryption Envelope v2](https://github.com/hyperledger/aries-rfcs/blob/main/features/0587-encryption-envelope-v2/README.md) 
* [0593: JSON-LD Credential Attachment format for requesting and issuing credentials](https://github.com/hyperledger/aries-rfcs/blob/main/features/0593-json-ld-cred-attach/README.md) 
* [0627: Static Peer DIDs](https://github.com/hyperledger/aries-rfcs/blob/main/features/0627-static-peer-dids/README.md) 
* [0646: W3C Credential Exchange using BBS+ Signatures](https://github.com/hyperledger/aries-rfcs/blob/main/features/0646-bbs-credentials/README.md) 
* [0032: Message Timing](https://github.com/hyperledger/aries-rfcs/blob/main/features/0032-message-timing/README.md) 
* [0021: DIDComm Message Anatomy](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0021-didcomm-message-anatomy/README.md) 
* [0028: Introduce Protocol 1.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0028-introduce/README.md) 
* [0056: Service Decorator](https://github.com/hyperledger/aries-rfcs/blob/main/features/0056-service-decorator/README.md) 
* [0067: DIDComm DID document conventions](https://github.com/hyperledger/aries-rfcs/blob/main/features/0067-didcomm-diddoc-conventions/README.md) 
* [0074: DIDComm Best Practices](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0074-didcomm-best-practices/README.md) 
* [0124: DID Resolution Protocol 0.9](https://github.com/hyperledger/aries-rfcs/blob/main/features/0124-did-resolution-protocol/README.md) 
* [0270: Interop Test Suite](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0270-interop-test-suite/README.md) 
* [0309: DIDAuthZ](https://github.com/hyperledger/aries-rfcs/blob/main/features/0309-didauthz/README.md) 
* [0317: Please ACK Decorator](https://github.com/hyperledger/aries-rfcs/blob/main/features/0317-please-ack/README.md) 
* [0335: HTTP Over DIDComm](https://github.com/hyperledger/aries-rfcs/blob/main/features/0335-http-over-didcomm/README.md) 
* [0346: DIDComm Between Two Mobile Agents Using Cloud Agent Mediator](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0346-didcomm-between-two-mobile-agents/README.md) 
* [0351: Purpose Decorator](https://github.com/hyperledger/aries-rfcs/blob/main/features/0351-purpose-decorator/README.md) 
* [0511: Credential-Manifest Attachment format for requesting and presenting credentials](https://github.com/hyperledger/aries-rfcs/blob/main/features/0511-dif-cred-manifest-attach/README.md) 
