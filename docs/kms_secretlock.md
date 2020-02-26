# KMS, SecretLock and Crypto capabilities

Keys used in the Aries framework must be secured from being compromised during their usage or storage. This goal can
be achieved by avoiding the exchange of raw key bytes as an argument of functions requiring keys and instead accept a
key reference. The functions in question are usually crypto operations that require these keys. One of the libraries 
that provides a clear separation between keys and crypto operations is [Tink](https://github.com/google/tink). Keys in 
Tink are referenced by Key Handles and are linked to primitives representing the crypto operation. In a nutshell, a 
user will get a key handle from a source (or default key templates offered by Tink) and passes it to the crypto function
that needs the underlying key. Tink is used in the default Crypto and KMS implementations of the framework to hide key 
content from being accessed externally.

The KMS service should handle how to fetch the key for the crypto operation needed. Therefore, it must never return 
raw key contents to the user. The default implementation makes use of Tink to get corresponding key handles discussed
above.

In addition to the Crypto and KMS services, there is a need to secure and lock keys to protect the identity of the
agent. The SecretLock service is offered in the framework for this purpose. It uses a master key to encrypt keys stored
locally (or in the cloud) and it can be itself protected, for example, by a passphrase.

To achieve these requirements, the following criteria must be met:
 - The KMS service should support providing a key reference (or keyset handle) whenever a key is required. It must not
   return or accept raw contents of keys within the framework and with the user.
 - The SecretLock service is needed to protect keys by encrypting them when being stored.
 - The SecretLock service must work with a master key that can be provided by the user.
 - The master key should also be encrypted to prevent its compromise. This should be optional in the SecretLock. For
   instance, a user may decide to use an unprotected master key for testing purposes but the recommended way is for the 
   master key to be secured.
 - An example of unlocking a master key by the KMS/SecretLock would be the use of a passphrase.
 - Finally the crypto services must only accept key references provided by the KMS to execute operations. They must not
   accept raw content of keys as function arguments.
 
The default Crypto service accepts key handles and delegate crypto operations to Tink. These key handles are a  
reference to real keys which are only available internally to Tink crypto operations. The default KMS service creates 
and manages these key handles and serves as a provider of these key handles to the crypto service. Although the default
Crypto and KMS services are implemented using Tink, the framework itself can accept any implementation being supplied 
to `aries.WithKMS(customKMSImplementaiton)` and `aries.WithCrypto(customCryptoImplementation)`.
 
There are several ways to prepare and use the new KMS and SecretLock services. The below sections describe each path:

## No SecretLock/KMS options

The framework default is no SecretLock or the use of a noop secret lock service. This means keys are
not securely stored in the keystore. To secure keys storage, one must create a secure SecretLock option and add it to 
the framework. See next sections for an example on how to pass one as a framework option.

For agents tools that use the framework, eg [agent rest](../cmd/aries-agent-rest) and [js worker](../cmd/aries-js-worker),
a custom SecretLock default implementation will be created to suit the target environment. More details will be added
about these in the future.

## Passing in a SecretLock option

The previous way will create a default no SecretLock instance that does not protect keys. It should only be used in tests. 
The recommended safe way is to create your own secure SecretLock instance by first creating your own encrypted master 
key file. This key can be generated via password expansion as shown in the example below. Once the file is created with
the protected master key, you can create your SecretLock service with a reader to the file and the masterLocker instance
used to encrypt the master key. You can then pass in the created SecretLock as an option to the framework.
Below is an example code snippet:

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

// keySize to be used to create master key
keySize := sha256.Size

// create, an optional salt
salt := make([]byte, keySize)
_, err = rand.Read(salt)
if err != nil {
    return err
}

// create a master lock to protect the master key (salt is optional)
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
mkReader, err := local.MasterKeyFromPath(fileName)
if err != nil {
    return err
}

// finally create a new instance of local secret lock service using masterLock (key wrapper) and mkReader
s, err := local.NewService(r, masterLocker)
if err != nil {
    return err
}

// finally create the framework with custom secret lock service created above
framework := aries.New(aries.WithSecretLock(s))
```

This New() call will create a default local KMS instance with the SecretLock service passed in as an option. This 
SecretLock instance protects the master key as it's encrypted. It is stored in a file for reuse.

## Passing in a custom KMS instance

The previous way created an Aries framework instance with a default KMS instance using a custom SecretLock option. 
If you prefer to create your own custom KMS, you can pass it in as an option as well. 
Below is an example (assuming SecretLock service and a StoreProvider were already created):

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