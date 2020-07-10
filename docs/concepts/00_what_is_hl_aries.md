# What is Hyperledger Aries?

Hyperledger Aries provides a shared, reusable, interoperable tool kit designed for initiatives and solutions focused on creating, transmitting and storing verifiable digital credentials. It is infrastructure for blockchain-rooted, peer-to-peer interactions. This project consumes the cryptographic support provided by Hyperledger Ursa, to provide secure secret management and decentralized key management functionality. (1)

## Where did Aries come from?

Hyperledger Aries is related to both Hyperledger Indy, which provides a resolver implementation, and Hyperledger Ursa, which it uses for cryptographic functionality. Aries will consume the cryptographic support provided by Ursa to provide both secure secret management and hardware security modules support. (2)

## Key Characteristics

- A blockchain interface layer (known as a resolver) for creating and signing blockchain transactions.
- A resolver can be seen as part of a larger component known as the VDRI:
  > Aries Verifiable Data Registry Interface: An interface for verifying data against an underlying ledger.
- A cryptographic wallet that can be used for secure storage of cryptographic secrets and other information (the secure storage tech, not a UI) used to build blockchain clients.
- An encrypted messaging system for allowing off-ledger interaction between those clients using multiple transport protocols.
- An implementation of ZKP-capable W3C verifiable credentials using the ZKP primitives found in Ursa.
- An implementation of the Decentralized Key Management System (DKMS) specification currently being incubated in Hyperledger Indy.
- A mechanism to build higher-level protocols and API-like use cases based on the secure messaging functionality described earlier.  (3)

## Protocols We Support

The following protocols are supported by Aries-Framework-Go.

- DIDExchange
- Introduce
- IssueCredential
- KMS
- Mediator
- Messaging
- OutOfBand
- PresentProof
- VDRI
- Verifiable

---
###### References

1. [Official library page](https://www.hyperledger.org/use/aries)
2. [Blog post annoucement](https://www.hyperledger.org/blog/2019/05/14/announcing-hyperledger-aries-infrastructure-supporting-interoperable-identity-solutions)
3. [Hyperledger Aries Wiki](https://wiki.hyperledger.org/display/ARIES/Hyperledger+Aries)

