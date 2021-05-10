# Aries Encrypted Storage

The Aries framework can be configured to use encrypted storage. [EDV](https://identity.foundation/confidential-storage/) server storage is supported right out of the box, but other custom encrypted storage configurations are possible - see below for details.

## Configuring Aries Framework with encrypted storage in Go Code

### Using an EDV server
The [EDV REST Provider](../component/storage/edv/restprovider.go) can be used to allow an Aries agent to store data in an EDV server of your choosing.
```
// Create an edv.EncryptedFormatter with the necessary key data and crypto data to handle the conversion between unencrypted and encrypted data.
// See https://github.com/hyperledger/aries-framework-go/blob/main/component/storage/edv/encryptedformatter_test.go#L88 for an example of how you can create the `jweEncrypter`, `jweDecrypter` and `macCrypto` objects.
// Note that the example only creates keys in memory and doesn't store them anywhere persistent.
// For any real application you will probably want to persist those keys somewhere in order to decrypt documents later after the keys have been wiped from memory.
encryptedFormatter := edv.NewEncryptedFormatter(jweEncrypter, jweDecrypter, macCrypto)

// Create an edv.RESTProvider to handle EDV server communication. It uses a single vault for all stores, and uses macCrypto for encrypted index creation.
// The vault specified below MUST already exist; edvRESTProvider won't create one for you.
edvRESTProvider := edv.NewRESTProvider("SomeEDVServerURL, "SomeVaultID", encryptedFormatter)

// Instantiate the framework with edvRESTProvider.
framework, err := aries.New(aries.WithStoreProvider(edvRESTProvider))
```

### Using the EDV data model without an EDV server
It's possible to make use of the EDV encrypted data format without using an EDV server by making use of the [Formatted Storage Provider](../component/storageutil/formattedstore/formattedstore.go) and the [EDV Encrypted Formatter](../component/storage/edv/encryptedformatter.go).
```
// Create an edv.EncryptedFormatter with the necessary key data and crypto data to handle the conversion between unencrypted and encrypted data.
// See https://github.com/hyperledger/aries-framework-go/blob/main/component/storage/edv/encryptedformatter_test.go#L88 for an example of how you can create the `jweEncrypter`, `jweDecrypter` and `macCrypto` objects.
// Note that the example only creates keys in memory and doesn't store them anywhere persistent.
// For any real application you will probably want to persist those keys somewhere in order to decrypt documents later after the keys have been wiped from memory.
encryptedFormatter := edv.NewEncryptedFormatter(jweEncrypter, jweDecrypter, macCrypto)

// Create the underlying storage provider for the Formatted Provider. This underlying storage provider is where the encrypted data will get stored. It can be any underlying storage provider - IndexedDB is used below as an example.
// Note: If you're using an EDV server (that supports the EDV REST API), you should not use the Formatted Provider and should instead directly use the EDV REST Provider (see the previous section). While it will technically work either way, passing an EDV REST Provider into a Formatted Provider will result in an unnecessary extra layer of encryption that will hurt performance.
indexedDBProvider, err := indexeddb.NewProvider("SomeName")

// Instantiate a Formatted Provider with indexedDBProvider (as the underlying provider) and the EDV encrypted formatter.
formattedProvider := formattedstore.NewProvider(indexedDBProvider, encryptedFormatter

// Instantiate the framework with formattedProvider.
framework, err := aries.New(aries.WithStoreProvider(formattedProvider))
```
### Other custom encrypted data formats
If desired, a custom encrypted data format can be used by creating a custom implementation of the Formatter interface and passing it in to `formattedstore.NewProvider(underlyingProvider, formatter)`.

## Optional Features

### Caching

For improved performance, you may want to enable caching by wrapping the storage provider in a [Cached Provider](../component/storageutil/cachedstore/cachedstore.go) before initializing Aries with it.

For example:
```
// Any storage provider can be used as a cache for the "main" or "expensive" storage provider. An in-memory provider is used here as an example.
memProvider := mem.NewProvider()

// Pass in the EDV REST Provider as the main provider and the in-memory provider as the cache provider.
cachedProvider := cachedstore.NewProvider(edvRESTProvider, memProvider)

// Instantiate the framework with cachedProvider.
framework, err := aries.New(aries.WithStoreProvider(formattedProvider))
```

## EDV server Extensions (Optional)
If you're using the [TrustBloc EDV server implementation](https://github.com/trustbloc/edv), then there are several [extensions](https://github.com/trustbloc/edv/blob/main/docs/extensions.md) that can be used to improve performance. Note that, as of writing, these extensions are either not officially supported by the spec, or are features at risk within the spec. Check the official EDV spec to see their current status.
### Batch Support
If you're using the batch extension, then you can take advantage of improved performance by setting up your storage provider as follows:

```
// Note the extra option supplied below at the end of the function.
edvRESTProvider := edv.NewRESTProvider("SomeEDVServerURL, "SomeVaultID", encryptedFormatter, edv.WithBatchEndpointExtension())

// Wrap the EDV REST Provider (started with the "batch endpoint" option in a batched storage provider, with a batch size limit of 100.
// This will enable automatic batching of data
batchedProvider := batchedstore.NewProvider(edvRESTProvider, 100)

// Optionally, you can then further wrap the batchedProvider in a Cached Provider:
// cachedProvider := cachedstore.NewProvider(batchedProvider, mem.NewProvider())

// Instantiate the framework with batchedProvider.
framework, err := aries.New(aries.WithStoreProvider(batchedProvider))

// Or, if you also used a Cached Provider:
// framework, err := aries.New(aries.WithStoreProvider(cachedProvider))

```

### Faster Querying
If you're using the "return full documents from queries" extension, then you can take advantage of improved performance by enabling the "full documents returned from queries" option in the EDV REST provider:

```
// Note the extra option supplied below at the end of the function.
// You can use this with the batch option described in the previous section by simply adding it to the function call, either before or after the "return full documents" option below. 
edvRESTProvider := edv.NewRESTProvider("SomeEDVServerURL, "SomeVaultID", encryptedFormatter, edv.WithFullDocumentsReturnedFromQueries())
```
