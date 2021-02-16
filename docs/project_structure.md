# Project Structure


The project's components are organized, conceptually, into 3 layers:
- Controller Bindings: provides APIs for framework users
- Service: handles protocol flows, dispatches to other layers
- Pluggable dependencies: components (DIDs, crypto, etc)

As a user, what do you do:
- Controller Bindings
  - initialize the framework (Aries framework object)
  - register for events using the Rest API or Native Go API
  - handle events
- Pluggable Components
  - Create custom plugins for components, inject them into the framework 
    
## Important Go Packages
- [Framework](../pkg/framework/aries): Initializes the framework with user provided or default options.
- [Client](../pkg/client): Defines DIDComm Protocol APIs for framework consumers.
- [Protocol Service](../pkg/didcomm/protocol/): Handles DIDComm Protocol messages including state transitions.
- [Message Service](../pkg/didcomm/messaging/): Dynamically handles incoming DIDComm messages by type and purpose.
- [Key Management Service](../pkg/kms): Handles agent key management including creation of keys and signing of messages.
- [DID Method](../pkg/didmethod): Provides support for DID Methods. Currently, framework supports HTTP and Peer DID Methods.
- [Storage](../pkg/storage): Provides agent data storage options. Currently, in-memory storage is supported by default. [Encrypted
  storage is also supported](encrypted_storage.md).
- [DIDComm Envelope](../pkg/didcomm/packer): Supports packing and unpacking of DIDComm message envelopes. 
- [Verifiable Credential](../pkg/doc/verifiable): Defines Verifiable Credentials and Presentations data model. 

