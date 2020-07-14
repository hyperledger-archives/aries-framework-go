# What is Hyperledger Aries?

Hyperledger Aries provides a shared, reusable, interoperable tool kit designed for initiatives and solutions focused on creating, transmitting and storing verifiable digital credentials. It is infrastructure for blockchain-rooted, peer-to-peer interactions. This project consumes the cryptographic support provided by Hyperledger Ursa, to provide secure secret management and decentralized key management functionality. _(1)_

## Where did Aries come from?

Hyperledger Aries is related to both Hyperledger Indy, which provides a resolver implementation, and Hyperledger Ursa, which it uses for cryptographic functionality. Aries will consume the cryptographic support provided by Ursa to provide both secure secret management and hardware security modules support. _(2)_

## Key Characteristics

- A blockchain interface layer (known as a resolver) for creating and signing blockchain transactions.
- A resolver can be seen as part of a larger component known as the VDRI:
  > Aries Verifiable Data Registry Interface: An interface for verifying data against an underlying ledger.
- A cryptographic wallet that can be used for secure storage of cryptographic secrets and other information (the secure storage tech, not a UI) used to build blockchain clients.
- An encrypted messaging system for allowing off-ledger interaction between those clients using multiple transport protocols.
- An implementation of ZKP-capable W3C verifiable credentials using the ZKP primitives found in Ursa.
- An implementation of the Decentralized Key Management System (DKMS) specification currently being incubated in Hyperledger Indy.
- A mechanism to build higher-level protocols and API-like use cases based on the secure messaging functionality described earlier.  _(3)_

## Supported Controllers

The following controllers are supported by Aries-Framework-Go.

### 1. DIDExchange Protocol

### 2. Introduce Protocol

This protocol describes how an intermediary can introduce two parties that it already knows, but that do not know each other.
_(4)_

### 3. IssueCredential Protocol

### 4. KMS

### 5. Mediator

### 6. Messaging

### 7. OutOfBand Protocol

### 8. PresentProof Protocol

### 9. VDRI

### 10. Verifiable

This controller allows for the creation, retrieval, validation and signing of [verifiable presentations](./01_terminologies.md#verifiable-presentation) and [verifiable credentials](./01_terminologies.md#verifiable-credential).

---
###### References

1. [Official library page](https://www.hyperledger.org/use/aries)
2. [Blog post annoucement](https://www.hyperledger.org/blog/2019/05/14/announcing-hyperledger-aries-infrastructure-supporting-interoperable-identity-solutions)
3. [Hyperledger Aries Wiki](https://wiki.hyperledger.org/display/ARIES/Hyperledger+Aries)
4. [Aries RFCs - Introduce](https://github.com/hyperledger/aries-rfcs/tree/master/features/0028-introduce)
