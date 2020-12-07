# Aries Encrypted Storage

The Aries framework can be configured to use encrypted storage. [An implementation conforming to the Store interface](../pkg/storage/store.go) that is capable of storing to an [EDV](https://identity.foundation/confidential-storage/) server is included, but custom implementations can be injected if desired.

## Configuring Aries Framework with EDV storage in Go Code
```

Before doingFor the `jweEncrypter`, `jweDecrypter` and `macCrypto` objects, see https://github.com/hyperledger/aries-framework-go/blob/master/pkg/storage/formattedstore/formattedstore_test.go#L46
// Create an edv.EncryptedFormatter with the necessary key data and crypto data to handle the conversion between unencrypted and encrypted data.
// See https://github.com/hyperledger/aries-framework-go/blob/master/pkg/storage/formattedstore/formattedstore_test.go#L46 for an example of how you can create the `jweEncrypter`, `jweDecrypter` and `macCrypto` objects.
// Note that the example only creates keys in memory and doesn't store them anywhere persistent.
// For any real application you will need to persist those keys somewhere in order to decrypt documents later after the keys have been wiped from memory.
encryptedFormatter := edv.NewEncryptedFormatter(jweEncrypter, jweDecrypter, macCrypto)

// Create an edv.RESTProvider to handle EDV server communication. It uses a single vault for all stores, and uses macCrypto for encrypted index creation.
// The vault MUST already exist; edv.RESTProvider won't create one for you.
edvRESTProvider, err := edv.NewRESTProvider("SomeEDVServerURL, "SomeVaultID, macCrypto)

// Create the FormattedProvider, which uses encryptedFormatter and edvRESTProvider.
formattedProvider, err := formattedstore.NewFormattedProvider(edvRESTProvider, encryptedFormatter, false)

// Instantiate the framework with the formattedProvider
framework, err := aries.New(aries.WithStoreProvider(formattedProvider))
```

## Optional Features

### Caching

For improved performance, you may want to enable caching by instantiating the `FormattedProvider` with the `WithCacheProvider` option.

For example:
```
memProvider := mem.NewProvider()

// Create the FormattedProvider with the WithCacheProvider option.
formattedProvider, err := formattedstore.NewFormattedProvider(edvRESTProvider, encryptedFormatter, false, WithCacheProvider(memProvider))
```

## EDV Extensions (Optional)
### Batch Write Support
As of writing, the [EDV](https://identity.foundation/confidential-storage/) specification does not include this feature (although it has been [brought up as a requested feature](https://github.com/decentralized-identity/confidential-storage/issues/138)).

The [TrustBloc EDV server implementation](https://github.com/trustbloc/edv) has an extension that supports this feature. If you're using it then you can take advantage of improved performance by enabling batch write support:

```
// Create the FormattedProvider with the WithBatchWrite option.
formattedProvider, err := formattedstore.NewFormattedProvider(edvRESTProvider, encryptedFormatter, false, WithBatchWrite(100))
```

### Return Full Documents on Query
As of writing, the [EDV](https://identity.foundation/confidential-storage/) specification does not include this feature (although it has been [brought up as a requested feature](https://github.com/decentralized-identity/confidential-storage/issues/137)).

The [TrustBloc EDV server implementation](https://github.com/trustbloc/edv) has an extension that supports this feature. If you're using it then you can take advantage of improved performance by enabling the "full documents returned from queries" option:

```
// Create the FormattedProvider with the WithFullDocumentsReturnedFromQueries option.
formattedProvider, err := formattedstore.NewFormattedProvider(edvRESTProvider, encryptedFormatter, false, WithFullDocumentsReturnedFromQueries())
```
