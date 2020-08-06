# Terminologies

### Agent

An agent, in the context of self-sovereign identity, acts as a delegate of an individual identity; holds cryptographic keys to prove this responsibility; and interacts with other agents.

_Reference: https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0004-agents_

### DID

Decentralized identifiers (DIDs) are a new type of identifier that enables verifiable, decentralized digital identity.
A DID identifies any subject (e.g., a person, organization, thing, data model, abstract entity, etc.) that the controller of the DID decides that it identifies.

_Reference: https://www.w3.org/TR/did-core/_

### DIDComm

This refers to the general idea about how [agents](#agent) communicate with each other.

_Reference: https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0005-didcomm#motivation_

### DID Document

A set of data describing the DID subject, including mechanisms, such as public keys and pseudonymous biometrics, that the DID subject or a DID delegate can use to authenticate itself and prove its association with the DID.
A DID document may also contain other attributes or claims describing the DID subject.

_Reference: https://www.w3.org/TR/did-core/#dfn-did-documents_

### Holder

Also known as a prover, a holder is the entity to whom an [issuer](#issuer) issues a credential. Although the holder can request or propose that a credential be issued to them, they may not always be the subjects of a credential. 

In the [PresentProof](./00_what_is_hl_aries.md#8-presentproof-protocol) flow, the prover prepares the proof and presents it to the [verifier](#verifier).

### Issuer

The entity that issues a [credential](#verifiable-credential) to a holder.

### KMS

This stands for Key Management Service and is responsible for securely storing sensitive agent information such as private keys, secrets and other private data.

_Reference: https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0440-kms-architectures_

### Mediator

A mediator is a participant in agent-to-agent message delivery. It can be seen as a router with mailbox features which cannot read the encrypted contents of the routed messages.

_Reference: https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0046-mediators-and-relays/README.md#summary_

### VDRI

An interface for verifying data against a trusted backing store such as a ledger or a database. A role a system might perform by mediating the creation and verification of relevant data which might be required to use [verifiable credentials](#verifiable-credential).

_Reference: https://www.w3.org/TR/vc-data-model/#dfn-verifiable-data-registries_

### Verifiable Credential

A verifiable credential can represent all of the same information that a physical credential represents. It is a tamper-evident credential that has authorship that can be cryptographically verified.
Examples of verifiable credentials include digital employee identification cards, digital birth certificates, and digital educational certificates.

_Reference: https://www.w3.org/TR/vc-data-model/#what-is-a-verifiable-credential_

### Verifiable Presentation

A verifiable presentation expresses data from one or more verifiable credentials, and is packaged in such a way that the authorship of the data is verifiable.

_Reference: https://www.w3.org/TR/vc-data-model/#presentations_

### Verifier

This is the entity who makes a request for a [credential](#verifiable-credential) or proof from a [holder](#holder) and verifies it.

_Reference: https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2#roles_
