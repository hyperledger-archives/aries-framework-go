# KMS, SecretLock and Crypto capabilities

Keys used in the Aries framework must be secured from being compromised during their usage or storage. This goal can be achieved by avoiding the exchange of raw key bytes as an argument of functions requiring keys and instead accept a key reference. The functions in question are usually crypto operations that require these keys. One of the libraries that provides a clear separation between keys and crypto operations is [Tink](https://github.com/google/tink). Keys in Tink are referenced by Key Handles and are linked to primitives representing the crypto operation. In a nutshell, a user will get a key handle from a source (or default key templates offered by Tink) and passes it to the crypto function that needs the underlying key. Tink is used in the default Crypto and KMS implementations of the framework to hide key content from being accessed externally.

The KMS service should handle how to fetch the key for the crypto operation needed. Therefore, it must never return raw key contents to the user. The default implementation makes use of Tink to get corresponding key handles discussed above.

In addition to the Crypto and KMS services, there is a need to secure and lock keys to protect the identity of the agent. The SecretLock service is offered in the framework for this purpose. It uses a master key to encrypt keys stored locally (or in the cloud) and it can be itself protected, for example, by a passphrase.

To achieve these requirements, the following criteria must be met:
 - The KMS service should support providing a key reference (or keyset handle) whenever a key is required. It must not return or accept raw contents of keys within the framework and with the user.
 - The SecretLock service is needed to protect keys by encrypting them when being stored.
 - The SecretLock service must work with a master key that can be provided by the user.
 - The master key should also be encrypted to prevent its compromise. This should be optional in the SecretLock. For instance, a user may decide to use an unprotected master key for testing purposes but the recommended way is for the master key to be secured.
 - An example of unlocking a master key by the KMS/SecretLock would be the use of a passphrase.
 - Finally, the crypto services must only accept key references provided by the KMS to execute operations. They must not accept raw content of keys as function arguments.
 
The default Crypto service accepts key handles and delegate crypto operations to Tink. These key handles are a reference to real keys which are only available internally to Tink crypto operations. The default KMS service creates and manages these key handles and serves as a provider of these key handles to the crypto service. Although the default Crypto and KMS services are implemented using Tink, the framework itself can accept any implementation being supplied to `aries.WithKMS(customKMSImplementaiton)` and `aries.WithCrypto(customCryptoImplementation)`.
 
There are several ways to prepare and use the new KMS and SecretLock services. The below sections describe each path:

## No SecretLock/KMS options

The framework default is no SecretLock or the use of a noop secret lock service. This means keys are not securely stored in the keystore. To secure keys storage, one must create a secure SecretLock option and add it to the framework. See next sections for an example on how to pass one as a framework option.

For agents tools that use the framework, eg [agent rest](../cmd/aries-agent-rest) and [js worker](../cmd/aries-js-worker), a custom SecretLock default implementation will be created to suit the target environment. More details will be added about these in the future.

## Passing in a SecretLock option

The previous way will create a default no SecretLock instance that does not protect keys. It should only be used in tests. The recommended safe way is to create your own secure SecretLock instance by first creating your own encrypted master key file. This key can be generated via password expansion as shown in the examples below. Once the file is created with the protected master key, you can create your SecretLock service with a reader to the file and the masterLocker instance used to encrypt the master key. You can then pass in the created SecretLock as an option to the framework. Below are two example code snippets:

#### Prep with MasterKey in a file
If the application has access to the file system, the master key can be secured and stored locally. Below is one way to create and protect one, load it from the filesystem and create a secret lock.
```
package mypackage

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
 
)

...

// hardcoded for purpose of demo, passphrase could be an argument or read from another source in your program
passphrase := "secretPassphrase"

// keySize to be used to create master key
keySize := sha256.Size

// create, an optional salt
salt := make([]byte, keySize)
_, err := rand.Read(salt)
if err != nil {
    return err
}

// create a master lock to protect the master key 
// (salt is optional, if using one, ensure it is stored and passed in for future uses)
masterLock, err := hkdf.NewMasterLock(passphrase, sha256.New, salt)
if err != nil {
    return err
}

// generate a random master key
masterKeyContent := make([]byte, keySize)
_, err = rand.Read(masterKeyContent)
if err != nil {
    return err
}

// encrypt it
masterKeyEnc, err := masterLock.Encrypt("", &secretlock.EncryptRequest{
    Plaintext: string(masterKeyContent)})

// create a file to store it
file, err := os.OpenFile("path/to/your/encrypted/masterKeyFile", os.O_WRONLY|os.O_CREATE, 0600)
if err != nil {
    return err
}

// write the encrypted master key in the file
_, err = file.Write([]byte(masterLockEnc.Ciphertext))
if err != nil {
    return err
}

fileName := file.Name()

err = file.Close()
if err != nil {
    return err
}

// create a master key reader from this file
// Note: Now that the protected master key file is created, future calls to aries.New()
//       start from the below lines + the masterLock creation above, ie the above code is for master key prep only.
mkReader, err := local.MasterKeyFromPath(fileName)
if err != nil {
    return err
}

// finally create a new instance of local secret lock service using masterLock (key wrapper) and mkReader
secLock, err := local.NewService(mkReader, masterLock)
if err != nil {
    return err
}

// finally create the framework with custom secret lock service created above
framework := aries.New(aries.WithSecretLock(secLock))
```

#### Prep with MasterKey in an env variable
If the application does not have access to the file system, the master key can be secured and set in an environment variable. Below is a way to create and protect one, load it from the environment variable and create a secret lock. The onus is on the application developer to store the protected master key in a persistent storage (ie DB storage or another persistent mechanism) for future reuse of the master key.
```
package mypackage
import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
 
)

...

// hardcoded for purpose of demo, passphrase could be an argument or read from another source in your program
passphrase := "secretPassphrase"

// keySize to be used to create master key
keySize := sha256.Size

// create, an optional salt
salt := make([]byte, keySize)
_, err := rand.Read(salt)
if err != nil {
    return err
}

// create a master lock to protect the master key
// (salt is optional, if using one, ensure it is stored and passed in for future uses)
masterLock, err := hkdf.NewMasterLock(passphrase, sha256.New, salt)
if err != nil {
    return err
}

// generate a random master key
masterKeyContent := make([]byte, keySize)
_, err = rand.Read(masterKeyContent)
if err != nil {
    return err
}

// encrypt it
masterKeyEnc, err := masterLock.Encrypt("", &secretlock.EncryptRequest{
    Plaintext: string(masterKeyContent)})

// create an environment variable key to set the master key
envPrefix  := "LOCAL_MK_"
masterKeyURI := "local://master/key/uri"
envKey := envPrefix + strings.ReplaceAll(masterKeyURI, "/", "_")

// now set the encrypted master key in env
// note: storing the master key in an env variable is temporary - ensure it's persisted 
//       somewhere else for future reuse
err = os.Setenv(envKey, masterLockEnc.Ciphertext)
if err != nil {
    return err
}

// get a reader from a valid env variable
// note: getting a reader `FromEnv` is helper utility function for envrionments 
//       that don't have access to the filesystem. The master key would be persisted, say in a DB storage, and
//       reloaded in an environment variable via the below call to prepare the SecretLock
mkReader, err := MasterKeyFromEnv(envPrefix, testKeyURI)

// finally create a new instance of local secret lock service using masterLock (key wrapper) and mkReader
secLock, err := local.NewService(mkReader, masterLock)
if err != nil {
    return err
}

// finally create the framework with custom secret lock service created above
framework := aries.New(aries.WithSecretLock(secLock))
```

This New() call will create a default local KMS instance with the SecretLock service passed in as an option. This SecretLock instance protects the master key as it's encrypted. It is stored in a file for reuse in the first example and in an environment variable in the second.

## Passing in a custom KMS instance

The previous way created an Aries framework instance with a default KMS instance using a custom SecretLock option. If you prefer to create your own custom KMS, you can pass it in as an option as well. Below is an example (assuming SecretLock service and a StoreProvider were already created):

```
package mypackage

import (
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/context"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

...

// create a new Context with pre built Storage provider and Secret lock instances
provider, err := context.New(
    context.WithSecretLock(prebuiltSecretLock),
    context.WithStorageProvider(prebuiltStorageProvider),
)
if err != nil {
    return err
}

// master key URI, for local KMS/SecretLock, prefix with `local-lock://`
masterKeyURI := "local-lock://custom/master/key/"

// create a custom KMS instance with this provider
customKMS, err := localkms.New(masterKeyURI, provider)
require.NoError(t, err)
require.NotEmpty(t, customKMS)

// finally create the framework using a KMSCreator function returning the above customKMS
a, err = aries.New(aries.WithKMS(func(ctx kms.Provider) (kms.KeyManager, error) {
    return customKMS, nil
}))
```

Aries framework will use the instance of customKMS passed in as an option instead of creating a default one.

## Interop with external keys

### Export Public signing keys []bytes from KMS
The default KMS implementation (in `localkms` package) supports exporting public signing keys in DER/IEEE-P1363 signature formats to allow signature verification outside of the KMS.

The following call is an example of creating and exporting a public P-256 key using IEEE-P1363 signature format:

```
// ... get/create kmsInstance as per previous sections
keyID, newKeyHandle, err := kmsInstance.Create(kms.ECDSAP256TypeIEEEP1363)
if err != nil {
    return err
}

pubKeyBytes, err := kmsInstance.ExportPubKeyBytes(ksID)

```
### Create and Export Public signing keys []bytes from KMS
To avoid calling the KMS's Create() then ExportPubKeyBytes() separately, a new function was created to call both in one call. It is called `CreateAndExportPubKeyBytes`, the following is an example use of this function:
```
// ... get/create kmsInstance as per previous sections

//
ksID, pubKeyBytes, err := kmsInstance.CreateAndExportPubKeyBytes(kms.ECDSAP256TypeIEEEP1363)

```

This function call creates a new keyset of type `kms.ECDSAP256TypeIEEEP1363`, stores it in the KMS and returns its correponding ksID along with the exported public key bytes in IEEE P1363 format.

### Convert Public Signing Keys []byte to Tink's keyset.Handle

The reverse of an export operation would be to get a keyset.Handle from a public key in raw []byte (DER or IEEE-P1363 signing format). 

The KMS service does not support importing public keys alone, it supports importing private keys (along with their public keys, see the next section for more information), but it can create a Tink `keyset.Handle` instance representing a public signing key to execute signatures verifications. This created `keyset.Handle` can only be used for verifying a signature, not signing a message as it doesn't contain the private key.

The following is an example of creating a Tink `keyset.Handle` instance that can be used by the `crypto` service to execute `Verify()` calls:

```
// ... get/create kmsInstance as per previous sections
pubKeyBytes, err := kmsInstance.ExportPubKeyBytes(ksID)
//
// ... exchange pubKeyBytes with other party
//
// the other party can then do the follwoing
pubKeyHandle, err := kmsInstance.PubKeyBytesToHandle(pubKeyBytes, kms.ECDSAP256TypeIEEEP1363)
if err != nil {
    return err
}
```

`pubKeyHandle` can then be passed to `crypto.Verify()` for signature verification. Note that the signing key format must be known prior to getting the public keyset.Handle instance. To verify using DER signature format, use `kms.ECDSAP256TypeDER`.


### Import Private Signing Keys into the KMS

Finally, to support using signing keys created outside of KMS/Tink, an import of private keys utility function in the default KMS implementation is available.

Below is an example of how to do just this for say a P-521 key with IEEE-P1363 signature format:

```
// ... get/create kmsInstance as per previous sections
// ... get ecdsa.Private instance of the private key (privKey below)
ksID, kh, err = kmsInstance.ImportPrivateKey(privKey, kms.ECDSAP521TypeIEEEP1363)
```

The returns of the call above are `ksID` which is a newly generated key ID in the KMS and `kh`, the Tink `keyset.Handle` needed to pass to `crypto.Sign()` call for signing. To get the public `keyset.Handle` for verification, you can call `kh.Public()`.

If `ksID` must be preset (for example when restarting an Aries and a KMS instance, you would like to re-use the same key IDs), you can add the optional `WithKeyID()` call with the preset key ID as shown below: 

```
// ... get/create kmsInstance as per previous sections
// ... get ecdsa.Private instance of the private key (privKey below)
// ... using a prset presetKeyID 
ksID, kh, err = kmsInstance.ImportPrivateKey(privKey, kms.ECDSAP521TypeIEEEP1363, WithKeyID(presetKeyID))
```

In the above call, importing the private key will try to use `presetKeyID` as the `ksID` and if it already exists then `err` will not be empty.
