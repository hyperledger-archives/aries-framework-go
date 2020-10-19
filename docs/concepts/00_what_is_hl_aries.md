# What is Hyperledger Aries?

Hyperledger Aries provides a shared, reusable, interoperable tool kit designed for initiatives and solutions focused on creating, transmitting and storing verifiable digital credentials. It is infrastructure for blockchain-rooted, peer-to-peer interactions. This project consumes the cryptographic support provided by Hyperledger Ursa, to provide secure secret management and decentralized key management functionality. _(1)_

## Where did Aries come from?

Hyperledger Aries is related to both Hyperledger Indy, which provides a resolver implementation, and Hyperledger Ursa, which it uses for cryptographic functionality. Aries will consume the cryptographic support provided by Ursa to provide both secure secret management and hardware security modules support. _(2)_

## Key Characteristics

- A blockchain interface layer (known as a resolver) for creating and signing blockchain transactions.
- A resolver can be seen as part of a larger component known as the [VDR](./01_terminologies.md#vdr):
  > Aries Verifiable Data Registry Interface: An interface for verifying data against an underlying ledger.
- A cryptographic wallet that can be used for secure storage of cryptographic secrets and other information (the secure storage tech, not a UI) used to build blockchain clients.
- An encrypted messaging system for allowing off-ledger interaction between those clients using multiple transport protocols.
- An implementation of ZKP-capable W3C verifiable credentials using the ZKP primitives found in Ursa.
- An implementation of the Decentralized Key Management System (DKMS) specification currently being incubated in Hyperledger Indy.
- A mechanism to build higher-level protocols and API-like use cases based on the secure messaging functionality described earlier.  _(3)_

## Supported Controllers

The following controllers are supported by Aries-Framework-Go.

### 1. DIDExchange Protocol
This protocol, at the core of Aries, allows [agents](./01_terminologies.md#agent) to establish relationships with each other for the purpose of sharing [DIDs](./01_terminologies.md#did) and [DID documents](./01_terminologies.md#did-document). _(4)_

### 2. Introduce Protocol

This protocol describes how an intermediary can introduce two parties that it already knows, but that do not know each other.
_(5)_

### 3. IssueCredential Protocol

This protocol enables an [issuer](./01_terminologies.md#issuer) to provide a [holder](./01_terminologies.md#holder) with a [verifiable credential](./01_terminologies.md#verifiable-credential). This process can be initiated by the issuer or holder. _(6)_

### 4. KMS

This controller provides access to the [key management service](./01_terminologies.md#kms) of an agent.

### 5. Mediator

This controller allows an agent to (un)register itself with a [mediator](./01_terminologies.md#mediator), view connection details and statuses.

The project can be used as a DIDComm [Router/Mediator](https://github.com/hyperledger/aries-framework-go/blob/master/docs/didcomm_mediator.md).

### 6. Messaging

This controller allows agents to (un)register message services with a message handler, send messages, reply to them and view all registered services.

### 7. OutOfBand Protocol

The controller for this protocol can be used when an [agent](./01_terminologies.md#agent) desires to connect with another but does not have a [DIDComm](./01_terminologies.md#didcomm) connection. _(7)_

### 8. PresentProof Protocol

This protocol enables a [verifier](./01_terminologies.md#verifier) to request a presentation of a proof from a [holder/prover](./01_terminologies.md#holder).

It focuses on the exchange of [verifiable presentations](./01_terminologies.md#verifiable-presentation) and does not concern itself with the structure of the documents which are being exchanged. _(8)_

### 9. VDR

This controller provides functionalities for the creation, retrieval and resolution of [DID documents](./01_terminologies.md#did-document) from a VDR (Verifiable Data Registry).

### 10. Verifiable

This controller allows for the creation, retrieval, validation and signing of [verifiable presentations](./01_terminologies.md#verifiable-presentation) and [verifiable credentials](./01_terminologies.md#verifiable-credential).

---
###### References

1. [Official library page](https://www.hyperledger.org/use/aries)
2. [Blog post annoucement](https://www.hyperledger.org/blog/2019/05/14/announcing-hyperledger-aries-infrastructure-supporting-interoperable-identity-solutions)
3. [Hyperledger Aries Wiki](https://wiki.hyperledger.org/display/ARIES/Hyperledger+Aries)
4. [Aries RFCs - DIDExchange](https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange)
5. [Aries RFCs - Introduce](https://github.com/hyperledger/aries-rfcs/tree/master/features/0028-introduce)
6. [Aries RFCs - IssueCredential Choreography Diagram](https://github.com/hyperledger/aries-rfcs/tree/master/features/0453-issue-credential-v2#choreography-diagram)
7. [Aries RFCs - Out-Of-Band](https://github.com/hyperledger/aries-rfcs/tree/master/features/0434-outofband)
8. [Aries RFCs - Present Proof](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
