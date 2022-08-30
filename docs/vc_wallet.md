# Verifiable Credential Wallet

The aries-framework-go project can be used as verifiable credential wallet which can be used to manage credentials and related data models.

## Standards

Here are the major specification followed by aries verifiable credential wallet interfaces,
* [Universal Wallet](https://w3c-ccg.github.io/universal-wallet-interop-spec/) - for wallet data models and interfaces.
* [Verifiable Presentation request Specifications](https://w3c-ccg.github.io/vp-request-spec/) - for credential queries.
* [Presentation Exchange](https://identity.foundation/presentation-exchange/) - for credential queries.
* [WACI Presentation Exchange](https://identity.foundation/waci-presentation-exchange/): Wallet and credential interaction standards using DIDComm.
* [Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/): For all the verifiable credential data model operations.
* [JSON-LD v1.1](https://w3c.github.io/json-ld-syntax/): For JSON-based Serialization for Linked Data.
* [Linked Data Proofs v1.0](https://w3c-ccg.github.io/ld-proofs/): For generating JSON-LD based linked data proofs.
* [Decentralized Identifiers (DIDs) v1.0](https://w3c.github.io/did-core/): For signing and verifying verifiable credentials and presentations.
* [WebKMS v0.7](https://w3c-ccg.github.io/webkms/): For implementing cryptographic key management systems for the wallet.
* [Decentralized Identifier Resolution (DID Resolution) v0.2](https://w3c-ccg.github.io/did-resolution/): Followed for resolving various decentralized identifiers.
* [Aries RFCS](#aries-rfcs): it follows many aries RFCs features like DIDComm, Out-Of-Band Messaging, Issue Credential Protocol, Present Proof Protocol, Messaging, Mediators etc.
* [DIDComm V2](https://identity.foundation/didcomm-messaging/spec/): Version 2 of DID Communication protocol for secured communication between wallet and issuer/relying party.
* [Credential Manifest](https://identity.foundation/credential-manifest/): Credential Manifests are a resource format that defines preconditional requirements, Issuer style preferences, Credential Style preferences and other facets User Agents utilize to help articulate and select the inputs necessary for processing and issuance of a specified credential.


## How it works

#### Wallet Profiles
The aries verifiable credential wallet provides multi-tenancy, where all wallet users can use their own storage, keys and key management systems. 
Each wallet user can create their wallet profiles customized to their storage types, keys and key management systems. 
Refer [profile section](#creating-and-updating-wallet-profiles) for more details on how to manage profiles. 

Note: Each wallet profiles can have their own storage types (like leveldb, couchdb, EDV etc) and KMS (local or remote).

![image](https://user-images.githubusercontent.com/29631944/126654261-dc49eb29-5fa9-46cf-b189-b1773064e496.png)

* Storage - Agent creates new storage for each wallet profile during profile creation. 
Storage type is typically same as agent's storage type, but a profile can also be created using already configured EDV if wallet user wish to use 
EDV.
* Key Management - Each wallet profile uses its own key management system which can be configured during profile creation.
    * Local KMS - a wallet profile can be created simply by providing local KMS passphrase where agent will create namespaced local KMS instance for corresponding wallet user. 
    Then wallet will use the profile's local KMS instance for all key operations.
    * Remote KMS (Web KMS) - a wallet profile can be created using key server URL in case of remote KMS. 
    Then wallet will use the profile's remote key server URL for all key operations.

#### Opening & Closing Wallet
All of the wallet operations involves storage & key management systems and they need to be unlocked to be used. 
So wallet provides mechanism for opening and closing the wallet to unlock and lock storage and key management systems. A wallet can only be opened by authorization parameters like local KMS passphrase, web kms auth, EDV auth etc based on wallet user's profile settings.
More details about how to open a wallet can be found [here](#opening-a-wallet)

Opening a wallet creates storage and KMS instances using wallet user's profile settings and returns an auth token which can be used for subsequent wallet operations.
When wallet closes or token expires, those storage and KMS instances will be destroyed and performing a wallet operation later on with previous token will return an error.  
 
#### Managing Wallet Contents
Wallet contents will be stored in storage provider configured during wallet's profile creation. The aries verifiable credential wallet implements various universal wallet interfaces and data models 
and they will be discussed in detail in data models and interfaces sections below.

#### Verifiable Credential Operations
The aries verifiable credential wallet provides various verifiable credentials operations based on universal wallet specifications like issue, prove, verify, derive etc.
Refer data models and interfaces sections below for more details.

#### DIDComm Operations
The aries verifiable credential wallet provides various DIDComm operations to perform secured exchange of credentials and other metadata between wallet and issuer/relying party.

## Creating and Updating Wallet Profiles
* A wallet profile with local KMS can be created by providing passphrase or secret lock service option.
* A wallet profile with Remote KMS can be created by providing secret lock service option.
* A wallet profile with EDV as storage type can be created by providing EDV storage options like edv server URL, Vault ID, encryption key ID and mac operation key ID.
This profile will use [aries EDV client implementation](https://github.com/hyperledger/aries-framework-go/blob/main/component/storage/edv) for performing encrypted data vault operations.

Refer Aries Go Docs for [ProfileOptions](https://github.com/hyperledger/aries-framework-go/blob/main/pkg/wallet/options.go#L33-L69) for different options for creating wallet profiles.

> Aries Go SDK Sample for creating wallet profile
```
// creating wallet profile using local KMS passphrase
err := vcwallet.CreateProfile(sampleUserID, ctx, wallet.WithPassphrase(samplePassPhrase))

// creating wallet profile using local KMS secret lock service
err = vcwallet.CreateProfile(sampleUserID, ctx, wallet.WithSecretLockService(mySecretLockSvc}))

// createing wallet profile using remote KMS & EDV
err := vcwallet.CreateProfile(sampleUserID, ctx,
wallet.WithKeyServerURL(keyServerURL), 
wallet.WithEDVStorage(edvServerURL, vaultID, encryptionKID,macKID))
```

Aries wallet APIs also provides ``UpdateProfile`` functions for updating wallet profiles. Care should be taken while using this function wallet might lose existing contents or keys by changing storage or key management systems.

## Opening a Wallet

Wallet can be opened by parameters related to profile settings of the wallet user.

For example,
* A wallet can be unlocked by local KMS passphrase or secret service only if wallet profile is configured to use local KMS for its key operations.
* A wallet user has to provide EDV unlock auth if wallet profile is configured to use EDV as a content store.

Opening a wallet returns a auth token which expires when wallet is closed or when life time of the token passes.

> Aries Go SDK Sample for opening a wallet for profile using local KMS settings - 1.
```
// creating vcwallet instance for user with local KMS settings.
myWallet, err := vcwallet.New(sampleUserID, ctx)

// opening a wallet with local KMS passphrase and getting a token for subsequent use.
err = myWallet.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))

```

> Aries Go SDK Sample for opening a wallet with expiry for profile using local KMS settings.
```
// creating vcwallet instance for user with local KMS settings.
myWallet, err := vcwallet.New(sampleUserID, ctx)

// opening a wallet with local KMS secret lock service and getting a token for subsequent use.
err = myWallet.Open(wallet.WithUnlockBySecretLockService(mySecretLockSvc), wallet.WithUnlockExpiry(10 * time.Second))

```

> Aries Go SDK Sample for opening a wallet for profile using web KMS.
```
// creating vcwallet instance for user with web KMS settings.
myWallet, err := vcwallet.New(sampleUserID, ctx)

// opening a wallet with web kms auth options and getting a token for subsequent use.
err = myWallet.Open(wallet.WithUnlockWebKMSOptions(opts...))

```

> Aries Go SDK Sample for opening a wallet for profile using web KMS & EDV.
```
// creating vcwallet instance for user with web KMS settings.
myWallet, err := vcwallet.New(sampleUserID, ctx)

// opening a wallet with web kms auth options and getting a token for subsequent use.
err = myWallet.Open(wallet.WithUnlockWebKMSOptions(opts...), wallet.WithUnlockEDVOptions(opts...))

```

Refer Go Docs for [UnlockOptions](https://github.com/hyperledger/aries-framework-go/blob/main/pkg/wallet/options.go#L92-L140) various wallet unlock options.


## Closing a Wallet

A wallet can be closed by simply calling ``Close`` function on wallet. It returns `true` when wallet is closed or `false` if wallet is already closed.

> Aries Go SDK Sample for closing a wallet.
```
// creating vcwallet instance for user with local KMS settings.
myWallet, err := vcwallet.New(sampleUserID, ctx)

// opening a wallet with local KMS passphrase and getting a token for subsequent use.
err = myWallet.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))

//... perform your operation

// close the wallet,
ok := myWallet.Close() // returns true

```


## Supported Data Models
Currently aries verifiable credential wallet supports following data models from universal wallet,
* [Collection](https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection) - used for grouping wallet contents. Once added to the wallet content store, the collection ID can be used to map a content of any type. 
So a customized request can be sent to the wallet to get list of all the contents mapped to a given collection ID and content type. 
For example, getting list of credentials from wallet for a collection called 'My Financial Credentials'. 
* [Credential](https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential) - a verifiable credential data model. Once saved, the ID of the credential can be used directly for various operations verify, prove, derive etc.
* [DIDResolutionResponse](https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse) - a DID document resolution data model which can be saved in wallet for subsequent use for issue, prove, derive, verify operations.
Wallet will use DID document resolution data model from content store while resolving DIDs and it falls back to agent's VDR only if it is not found. This model will be very handy for offline usage of wallet. 
* [Metadata](https://w3c-ccg.github.io/universal-wallet-interop-spec/#metadata) - can be used to save any wallet implementation specific custom data. 
For example, saving user's default signing profile info like signature type, controller, verification method.
* [Connection](https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection) - used for saving DIDComm connections.
* [Key](https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key) - key data model, once added to wallet private key from this data model will be imported into wallet profile's key management system. 
Supports both JWK (all curve types supported by aries framework go) & Base58 (Ed25519Signature2018 and Bls12381G1Key2020 key types). This data model is useful in importing keys into wallet.

## Wallet Interfaces
The aries verifiable credential wallet provides provides various wallet interfaces including the ones implemented from universal wallet specifications.

#### [Add](https://w3c-ccg.github.io/universal-wallet-interop-spec/#add)
This interface to be used for adding a data model to the wallet. Except `Key` data model all the data models will be added wallet content store. 
In case of `Key` data model, private key from data model gets imported into wallet profile's key management system.

Params,
* content type - type of the data model
* content - raw content
* options - like collection ID

Returns,
* error - if operation fails.


 > Aries Go SDK Sample for adding a content to wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // add credential to wallet.
 err = myWallet.Add(wallet.Credential, rawCredential)
 
 // add credential to wallet with collection ID.
 err = myWallet.Add(wallet.Credential, sampleCredential,  wallet.AddByCollection(collectionID))
 
 // add a DID Document.
 err = myWallet.Add(wallet.DIDResolutionResponse, resolvedDID)
 
 // close wallet.
 ok = myWallet.Close()
  
 ```
Note: It is always recommended that a data model which is being added to wallet content store has an ID. If a data model does not have an ID then wallet will use UUID as a key (for remove, get operations).
User `GetAll` interface to list wallet contents and their keys.


#### [Remove](https://w3c-ccg.github.io/universal-wallet-interop-spec/#remove)
Removes wallet content by ID from wallet content store. This interface is not supported for `Key` data model since aries KMS doesn't support key remove operations.

Params,
* content type - type of the data model
* content ID - ID of the wallet content. For example, credential ID in case of credential data model.

Returns,
* error - if operation fails.

 > Aries Go SDK Sample for removing a content from wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // remove a credential from wallet.
 err = myWallet.Remove(wallet.Credential, credentialID)
 
 // remove a Metadata from wallet.
 err = myWallet.Remove(wallet.Metadata, metadata)
 
 // close wallet.
 ok = myWallet.Close()
  
 ```
 
#### Get
Gets a wallet content by ID from wallet content store. This interface is not supported for `Key` data model.

Params,
* content type - type of the data model
* content ID - ID of the wallet content. For example, credential ID in case of credential data model.

Returns,
* json.RawMessage - raw wallet content.
* error - if operation fails or if data not found.

 > Aries Go SDK Sample for getting a content by ID from wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // get a credential from wallet.
 credential, err = myWallet.Get(wallet.Credential, credentialID)
 
 // get a connection from wallet.
 connection, err = myWallet.Get(wallet.Connection, connectionID)
 
 // close wallet.
 ok = myWallet.Close()
  
 ```
 
#### GetAll
Gets all content from wallet content store for given content type. This interface is not supported for `Key` data model.

Params,
* content type - type of the data model
* options - collection ID to filter results by collection ID

Returns,
* map[string]json.RawMessage - map of content keys to raw contents.
* error - if operation fails.

 > Aries Go SDK Sample for getting all contents from wallet for given content type.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // get all credentials from wallet for given collection ID.
 credentials, err = myWallet.GetAll(wallet.Credential, wallet.FilterByCollection(collectionID))
 
 // get all connections from wallet.
 connections, err = myWallet.Get(wallet.Connection)
 
 // close wallet.
 ok = myWallet.Close()
  
 ```

#### [Issue](https://w3c-ccg.github.io/universal-wallet-interop-spec/#issue)
Adds proof to a credential and returns verifiable credential as a response. 

Params,
* credential - raw credential to which proof has to be added.
* options - proof options.
    * controller - DID to be for signing.
    * verification method (optional) - is the URI of the verificationMethod used for the proof. By default controller public key matching 'assertion'. 
    * created (optional) - created date of the proof. By default, current system date will be used.
    * domain (optional) - is operational domain of a digital proof.
    * challenge (optional) -  is a random or pseudo-random value option for generating digital proof.
    * proof type (optional) - is signature type used for signing. Default, Ed25519Signature2018.
    * proof representation (optional) -  is type of proof data expected. Default, "proofValue".

Returns,
* *verifiable.Credential - credential issued.
* error - if operation fails.

 > Aries Go SDK Sample for issuing a credential from wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // Adding proof to raw credential using controller.
 vc, err := myWallet.Issue(rawCredential, &wallet.ProofOptions{
                                   			Controller: myDID,
                                   		})
 
 // close wallet.
 ok = myWallet.Close()
  
 ``` 

#### [Verify](https://w3c-ccg.github.io/universal-wallet-interop-spec/#verify)
Verifies a given verifiable credential or verifiable presentation.

Params,
* options - proof options.
    * store credential  - ID of the stored credential from wallet.
    * raw credential  - raw JSON bytes of verifiable credential.
    * raw presentation  - raw JSON bytes of verifiable presentation.

Returns,
* bool - true if verified.
* error - if verification fails.

 > Aries Go SDK Sample for issuing a credential using wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // Verifying a credential from wallet content store.
 verified, err := myWallet.Verify(wallet.WithStoredCredentialToVerify("http://example.edu/credentials/1872"))
 
 // Verifying a raw credential.
 verified, err = myWallet.Verify(wallet.WithRawCredentialToVerify(credentialBytes))
 
 // Verifying a raw presentation.
 verified, err = myWallet.Verify(wallet.WithRawPresentationToVerify(rawPresentation))
   
 // close wallet.
 ok = myWallet.Close()
  
 ``` 

#### [Prove](https://w3c-ccg.github.io/universal-wallet-interop-spec/#prove)
Produces a Verifiable Presentation.

Params,
* credential options - various options to present credentials.
    * stored credentials - list of credential IDs from wallet. 
    * raw credentials - list of raw JSON bytes of credentials. 
    * credentials - list of aries verifiable credential data models.
    * presentation - aries verifiable presentation data model.
    * raw presentation  - raw JSON bytes of verifiable presentation.
* options - proof options.
    * controller - DID to be for signing.
    * verification method (optional) - is the URI of the verificationMethod used for the proof. By default controller public key matching 'authentication'. 
    * created (optional) - created date of the proof. By default, current system date will be used.
    * domain (optional) - is operational domain of a digital proof.
    * challenge (optional) -  is a random or pseudo-random value option for generating digital proof.
    * proof type (optional) - is signature type used for signing. Default, Ed25519Signature2018.
    * proof representation (optional) -  is type of proof data expected. Default, "proofValue".
Refer [Go Docs](https://github.com/hyperledger/aries-framework-go/blob/main/pkg/wallet/options.go#L157-L197) for more details.

Returns,
* *verifiable.Presentation - presentation produced of aries verifiable presentation data model type.
* error - if operation fails.

 > Aries Go SDK Sample for proving credentials using wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // Producing a presentation using credentials in wallet content store.
 vp, err := myWallet.Prove(&wallet.ProofOptions{Controller: myDID}, wallet.WithStoredCredentialsToProve(id1, id2, id3, id4))
 
 // Producing a presentation using raw credentials.
 vp, err := myWallet.Prove(&wallet.ProofOptions{Controller: myDID}, wallet.WithRawCredentialsToProve(raw1, raw2))
 
 // Producing a presentation using mixed options.
 vp, err := myWallet.Prove(&wallet.ProofOptions{Controller: myDID}, 
                               wallet.WithStoredCredentialsToProve(id1, id2, id3, id4), 
                               wallet.WithRawCredentialsToProve(raw1, raw2),
                            )
   
 // close wallet.
 ok = myWallet.Close()
  
 ``` 

#### [Derive](https://w3c-ccg.github.io/universal-wallet-interop-spec/#derive)
Derives a credential and returns response credential.

Params,
* credential to derive - various options to provide credential to be derived from.
    * store credential  - ID of the stored credential from wallet.
    * raw credential  - raw JSON bytes of verifiable credential.
    * credential  - aries verifiable credential data model.
* derive options - options to derive.
    * frame - JSON-LD frame used for deriving (selective disclosure).
    * nonce -  to prove uniqueness or freshness of the proof. 

Returns,
* *verifiable.Credential - credential derived of aries verifiable credential data model type.
* error - if operation fails.

 > Aries Go SDK Sample for deriving credentials using wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // Derive a credential from wallet content store.
 derivedVC, err := myWallet.Derive(wallet.FromStoredCredential("http://example.edu/credentials/1872"),
                            			&wallet.DeriveOptions{
                            				Nonce: nonce,
                            				Frame: frameDoc,
                            			})
 
 // Derive a credential from a raw credential.
 derivedVC, err := myWallet.Derive(wallet.FromRawCredential(rawCredential),
                            			&wallet.DeriveOptions{
                            				Nonce: nonce,
                            				Frame: frameDoc,
                            			})
 
 // Derive a credential from credential object.
 derivedVC, err := myWallet.Derive(wallet.FromCredential(credentialObj),
                            			&wallet.DeriveOptions{
                            				Nonce: nonce,
                            				Frame: frameDoc,
                            			})
   
 // close wallet.
 ok = myWallet.Close()
  
 ``` 

#### CreateKeyPair
Creates key pair inside a wallet, imports private key into wallet and returns key ID and public key bytes.

Params,
* key Type - all supported [key types](https://github.com/hyperledger/aries-framework-go/blob/34ff560ed041fd9d3255a0c8c7f99c584c1c0a74/pkg/kms/api.go#L125-L171) by aries.

Returns,
* KeyPair - key pair result.
    * Key ID
    * Public Key
* error - if operation fails.

 > Aries Go SDK Sample for creating key pair using wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // Create ED52519 key pair.
 keyPair, err := myWallet.CreateKeyPair(kms.ED52519)
   
 // close wallet.
 ok = myWallet.Close()
  
 ``` 

#### [Query](https://w3c-ccg.github.io/universal-wallet-interop-spec/#query)
Performs credential query in the wallet.

Supported query types 
* [QueryByExample](https://w3c-ccg.github.io/vp-request-spec/#query-by-example)
* [QueryByFrame](https://github.com/w3c-ccg/vp-request-spec/issues/8)
* [PresentationExchange](https://identity.foundation/presentation-exchange/)
* [DIDAuth](https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request)

Params,
* queries - in vp-request-spec query list format. Supports mutliple queries
 > Sample queries
```
  query: [{
      type: 'APopularQueryType',
      // query details ...
    }, {
      type: 'AnotherQueryType',
      // query details ...
    }]
  
 ``` 
 
 Returns,
 * []*verifiable.Presentation - list of verifiable presentations. 
 Typically returns single presentation, but if PresentaionExchange is mixed with other query types then response may contain multiple presentations ([scenario explaind here](https://github.com/w3c-ccg/universal-wallet-interop-spec/issues/85)).
 
  > Aries Go SDK Sample for querying credentials from wallet.
  ```
  // creating vcwallet instance.
  myWallet, err := vcwallet.New(sampleUserID, ctx)
  
  // open wallet.
  err = myWallet.Open(...)
  
  // Query using QueryByExample.
  results, err := myWallet.Query([]*wallet.QueryParams{{Type: "QueryByExample", Query: exampleQuery}})
  
  // Query using QueryByFrame.
  results, err = myWallet.Query([]*wallet.QueryParams{{Type: "QueryByFrame", Query: frameQuery}})
  
  // Query using PresentationExchange.
  results, err = myWallet.Query([]*wallet.QueryParams{{Type: "PresentationExchange", Query: presentationDefn}})
  
  // Multiple QueryByExample queries.
  results, err = myWallet.Query([]*wallet.QueryParams{
    {Type: "QueryByExample", Query: exampleQuery1}},
    {Type: "QueryByExample", Query: exampleQuery2}},
    {Type: "QueryByExample", Query: exampleQuery3}},
  )
    
  // Mixed queries.
  results, err = myWallet.Query([]*wallet.QueryParams{
    {Type: "QueryByExample", Query: exampleQuery1}},
    {Type: "QueryByFrame", Query: exampleQuery2}},
    {Type: "QueryByExample", Query: exampleQuery3}},
  )
      
  // close wallet.
  ok = myWallet.Close()
   
  ``` 

#### [Connect](https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md)
Performs out of band DID exchange from wallet by accepting out of band invitation.

Params,
* invitation - out of band invitation from inviter.
* connect options - for out of band accept invitation.
    * MyLabel - label to be shared with the other agent during the subsequent did-exchange.
    * RouterConnections - option to provide for router connections to be used.
    * ReuseConnection -  option to provide DID to be used when reusing a connection.
    * ReuseAnyConnection - option to use any recognized DID in the services array for a reusable connection.
    * Timeout - option to provide timeout to wait for connection status to be completed.

Returns,
* connectionID - ID of the connection established.
* error - if operation fails.

 > Aries Go SDK Sample for performing DID connect from wallet.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // accept an invitation from wallet, perform DID connect and return connection ID.
 connectionID, err := myWallet.Connect(oobInvitation, wallet.WithConnectTimeout(30 * time.Second), wallet.WithMyLabel("alice wallet"))
   
 // close wallet.
 ok = myWallet.Close()
  
 ``` 

#### [ProposePresentation](https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposepresentation)
Proposing presentation from wallet to initiate WACI share flow.

Params,
* invitation - out of band invitation from inviter.
* options - for sending propose presentation message.
    * FromDID - option to provide customized from DID for sending propose presentation message.
    * Timeout - option to provide timeout duration to wait for request presentation response from relying party.

Returns,
* DIDCommMsg - request presentation message from relying party.
* error - if operation fails.

 > Aries Go SDK Sample for sending propose presentation message from wallet to relying party.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // accept an invitation from wallet, perform DID connect, send propose presentation message, wait and 
 // return request presentation message response from relying party.
 connectionID, err := myWallet.ProposePresentation(oobInvitation, wallet.WithInitiateTimeout(80 * time.Second), wallet.WithFromDID("did:example:wallet"))
   
 // close wallet.
 ok = myWallet.Close()
  
 ``` 
 
 #### [PresentProof](https://w3c-ccg.github.io/universal-wallet-interop-spec/#presentproof)
 Presenting proof to relying party from wallet for WACI share flow.
 
 Params,
 * threadID - thread ID of ongoing credential interaction with a relying party.
 * presentation - presentation to be sent to relying party.
 
 Returns,
 * error - if operation fails.
 
 ######TODO: support for ack message from relying party to be added for wallet redirects.
 
  > Aries Go SDK Sample for sending present proof message from wallet to relying party.
  ```
  // creating vcwallet instance.
  myWallet, err := vcwallet.New(sampleUserID, ctx)
  
  // open wallet.
  err = myWallet.Open(...)
  
  // send presentation to relying party as present proof message attachment for ongoing credential interaction.
  connectionID, err := myWallet.PresenProof(threadID, presentation)
    
  // close wallet.
  ok = myWallet.Close()
   
  ``` 

#### [ProposeCredential](https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposecredential)
Sends propose credential message from wallet to issuer, waits for offer credential message from issuer and returns incoming message.

Params,
* invitation - out of band invitation from inviter.
* options - for sending propose presentation message.
  * FromDID - option to provide customized from DID for sending propose presentation message.
  * ConnectOptions - customized options for accepting invitation..
  * Timeout - option to provide timeout duration to wait for offer credential message from issuer.

Returns,
* DIDCommMsg - offer credential message from issuer.
* error - if operation fails.

> Aries Go SDK Sample for sending propose credential message from wallet to issuer.
 ```
 // creating vcwallet instance.
 myWallet, err := vcwallet.New(sampleUserID, ctx)
 
 // open wallet.
 err = myWallet.Open(...)
 
 // accept an invitation from wallet, perform DID connect, send propose credential message, wait and 
 // return offer credential message response from issuer.
 connectionID, err := myWallet.ProposeCredential(oobInvitation, wallet.WithInitiateTimeout(80 * time.Second), wallet.WithFromDID("did:example:wallet"))
   
 // close wallet.
 ok = myWallet.Close()
  
 ``` 


#### [RequestCredential](https://w3c-ccg.github.io/universal-wallet-interop-spec/#requestcredential)
Sends request credential message from wallet to issuer and optionally waits for credential response.

Params:
* thID: thread ID (action ID) of offer credential message previously received.
* concludeInteractionOptions: options to conclude interaction like presentation to be shared etc.
  * rawPresentation - requesting credential from raw credential.
  * presentation presenting proof or requesting credential from verifiable presentation instance. This option takes precedence when provided with other options.
  * waitForDone - if provided then wallet will wait till it gets acknowledgement or problem report from other party. 
  * timeout - time duration to wait for status to be done or abanoned.

Returns:
* Credential interaction status containing status, redirectURL.
* error if operation fails.

> Aries Go SDK Sample for sending request credential message from wallet to issuer.
  ```
  // creating vcwallet instance.
  myWallet, err := vcwallet.New(sampleUserID, ctx)
  
  // open wallet.
  err = myWallet.Open(...)
  
  // send request credential message to issuer for ongoing credential interaction.
  connectionID, err := myWallet.RequestCredential(threadID, wallet.FromPresentation(application))
    
  // close wallet.
  ok = myWallet.Close()
   
  ``` 

#### ResolveCredentialManifest
Resolves given credential manifest by credential response or credential.
Supports: https://identity.foundation/credential-manifest/

Params,
* manifest: Credential manifest data model in raw format.
* resolve: to provide credential response or credential to resolve.

Returns,
* list of resolved descriptors.
* error if operation fails.

> Aries Go SDK Sample for resolving credential manifest by response.
  ```
  // creating vcwallet instance.
  myWallet, err := vcwallet.New(sampleUserID, ctx)
  
  // open wallet.
  err = myWallet.Open(...)
  
  // resolve credential manifest by raw credential response.
  connectionID, err := myWallet.ResolveCredentialManifest(threadID, wallet.ResolveRawResponse(response))
    
  // close wallet.
  ok = myWallet.Close()
   
  ``` 

## Controller Bindings
Aries command controller supports all verifiable credential wallet features with many more customization options like Authorization Capabilities (ZCAP-LD) feature for wallet's EDV and WebKMS components.

Refer [Go Docs](https://github.com/hyperledger/aries-framework-go/blob/main/pkg/controller/command/vcwallet/command.go) for package for more details.


#### JavaScript
Aries verifiable credential wallet is [available](https://github.com/hyperledger/aries-framework-go/blob/main/cmd/aries-js-worker/src/aries.js#L1080-L1273) as both Aries JavaScript WebAssembly and REST JS versions.
  > Sample Aries JS wallet operations.
  ```
  
// create agent instance
let agent = new Agent.Framework(agentOpts)

// create profile
await agent.vcwallet.createProfile({userID, keyStoreURL, edvConfiguration})

// open wallet
let auth = await agent.vcwallet.open({userID, webKMSAuth, edvUnlocks, expiry})

// add content
await agent.vcwallet.add({userID, auth, contentType, collectionID, content})

// get content
let {content} = await agent.vcwallet.get({userID, auth, contentType, contentID})

// get all content
let {contents} = await agent.vcwallet.getAll({userID, auth, contentType})

// remove content
let {content} = await agent.vcwallet.remove({userID, auth, contentType, contentID})

// query by QueryByExample & QueryByFrame
let {results} = await agent.vcwallet.query({userID: this.user, auth, [{
        "type": "QueryByFrame",
        "credentialQuery": [{
            "reason": "Please provide your Passport details.",
            "frame": {
                "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1", "https://w3id.org/security/bbs/v1"],
                "type": ["VerifiableCredential", "PermanentResidentCard"],
                "@explicit": true,
                "identifier": {},
                "issuer": {},
                "issuanceDate": {},
                "credentialSubject": {"@explicit": true, "name": {}, "spouse": {}}
            },
            "trustedIssuer": [{"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f", "required": true}],
            "required": true
        }]
    }, {
    "type": "QueryByExample",
        "credentialQuery": [{
        "reason": "Please present your valid degree certificate.",
        "example": {
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
            "type": ["UniversityDegreeCredential"],
            "trustedIssuer": [
                {"issuer": "urn:some:required:issuer"},
                {
                    "required": true,
                    "issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f"
                }
            ],
            "credentialSubject": {"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"}
        }
    }]
}
]})


// issue credential
let vc = await agent.vcwallet.issue({userID, auth, credential, {controller}})

// verify credential
let verified = await agent.vcwallet.verify({userID auth, storedCredentialID, rawCredential, presentation})

// prove credential
let vp = await agent.vcwallet.prove({userID, auth, storedCredentials, rawCredentials, presentation, {controller}})

// derive credential
let derived = await agent.vcwallet.derive({userID, auth, storedCredentialID, rawCredential, deriveOption})

// create key pair
let vc = await agent.vcwallet.createKeyPair({userID, auth, keyType})

// accept invitation and connect
let connection = await agent.vcwallet.connect({userID, auth, invitation})

// send propose presentation message from wallet for WACI share flow.
let requestPresentationMsg = await agent.vcwallet.proposePresentation({userID, auth, invitation, from})

// send present proof message from wallet for WACI share flow.
await agent.vcwallet.presentProof({userID, auth, threadID, presentation})

// accept invitation, send propose credential message and wait for offer presentation.
let offer = await wallet.proposeCredential(invitation, "did:example:holder", someTimeout)

// send request credential message, wait for ack and return credential response.
let fulfilment = await wallet.requestCredential(thID, presentation, waitForAck, someTimeout)

// close wallet
await agent.vcwallet.close({userID})
  
  ```

#### REST
Refer Aries Open API specifications for ``vcwallet`` operation ID.


#### Mobile (Work In Progress)
