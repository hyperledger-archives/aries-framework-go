/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2

	keyTagName = "Key"

	invalidTagName                 = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue                = `"%s" is an invalid tag value since it contains one or more ':' characters`
	failFormat                     = `failed to format %s "%s": %w`
	failFormatData                 = `failed to format data: %w`
	failDeformat                   = `failed to deformat %s "%s" returned from the underlying store: %w`
	failQueryUnderlyingStore       = "failed to query underlying store: %w"
	failGetValueUnderlyingIterator = "failed to get formatted value from the underlying iterator: %w"
)

var (
	errEmptyKey                     = errors.New("key cannot be empty")
	errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
		"it must be in the following format: TagName:TagValue")
)

// Formatter represents a type that can convert data between two formats.
type Formatter interface {
	Format(key string, value []byte, tags ...spi.Tag) (formattedKey string, formattedValue []byte,
		formattedTags []spi.Tag, err error)
	Deformat(formattedKey string, formattedValue []byte, formattedTags ...spi.Tag) (key string, value []byte,
		tags []spi.Tag, err error)
	// UsesDeterministicKeyFormatting indicates whether the formatted keys produced by this formatter can be
	// deterministically derived from the unformatted keys. If so, then FormattedProvider can take advantage of
	// certain performance optimizations.
	UsesDeterministicKeyFormatting() bool
}

// FormattedProvider is a spi.Provider that allows for data to be formatted in an underlying provider.
type FormattedProvider struct {
	provider   spi.Provider
	openStores map[string]*formatStore
	formatter  Formatter
	lock       sync.RWMutex
}

type closer func(name string)

// NewProvider instantiates a new FormattedProvider with the given spi.Provider and Formatter.
// The Formatter is used to format data before being sent to the Provider for storage.
// The Formatter is also used to restore the original format of data being retrieved from Provider.
func NewProvider(underlyingProvider spi.Provider, formatter Formatter) *FormattedProvider {
	formattedProvider := &FormattedProvider{
		provider:   underlyingProvider,
		formatter:  formatter,
		openStores: make(map[string]*formatStore),
	}

	return formattedProvider
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
// Store names are not case-sensitive.
func (f *FormattedProvider) OpenStore(name string) (spi.Store, error) {
	if name == "" {
		return nil, fmt.Errorf("store name cannot be empty")
	}

	name = strings.ToLower(name)

	f.lock.Lock()
	defer f.lock.Unlock()

	store, err := f.openStore(name)
	if err != nil {
		return nil, err
	}

	return store, nil
}

// SetStoreConfig sets the configuration on a store.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping spi.ErrStoreNotFound will be
// returned from the underlying provider.
func (f *FormattedProvider) SetStoreConfig(name string, config spi.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	name = strings.ToLower(name)

	tagsToFormat := make([]spi.Tag, len(config.TagNames))

	for i, tagName := range config.TagNames {
		tagsToFormat[i].Name = tagName
	}

	if !f.formatter.UsesDeterministicKeyFormatting() {
		tagsToFormat = append(tagsToFormat, spi.Tag{Name: keyTagName})
	}

	_, _, formattedTags, err := f.formatter.Format("", nil, tagsToFormat...)
	if err != nil {
		return fmt.Errorf("failed to format tag names: %w", err)
	}

	formattedTagNames := make([]string, len(tagsToFormat))

	for i, formattedTag := range formattedTags {
		formattedTagNames[i] = formattedTag.Name
	}

	formattedConfig := spi.StoreConfiguration{TagNames: formattedTagNames}

	err = f.provider.SetStoreConfig(name, formattedConfig)
	if err != nil {
		return fmt.Errorf("failed to set store configuration via underlying provider: %w", err)
	}

	// The EDV Encrypted Formatter implementation cannot deformat tag names directly. It needs to wrap them in
	// a stored value. The code below does this, which will allow GetStoreConfig to function in a FormattedProvider
	// regardless of what formatter is being used.

	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config into bytes: %w", err)
	}

	f.lock.Lock()
	defer f.lock.Unlock()

	err = f.storeStoreConfig(name, configBytes)
	if err != nil {
		return fmt.Errorf("failed to store store configuration: %w", err)
	}

	return nil
}

// GetStoreConfig gets the current store configuration.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned.
func (f *FormattedProvider) GetStoreConfig(name string) (spi.StoreConfiguration, error) {
	storeName := strings.ToLower(name)

	openStore := f.openStores[storeName]
	if openStore == nil {
		return spi.StoreConfiguration{}, spi.ErrStoreNotFound
	}

	// In order to support the more restrictive EDV formatter, we bypass the usual GetStoreConfig method and instead
	// get the unformatted tags by fetching them from the "store config" formatted store created earlier.

	store, err := f.OpenStore(storeName + "_formattedstore_storeconfig")
	if err != nil {
		return spi.StoreConfiguration{}, fmt.Errorf("failed to open the store config store: %w", err)
	}

	configBytes, err := store.Get("formattedstore_storeconfig")
	if err != nil {
		return spi.StoreConfiguration{},
			fmt.Errorf("failed to get store config from the store config store: %w", err)
	}

	var config spi.StoreConfiguration

	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return spi.StoreConfiguration{},
			fmt.Errorf("failed to unmarshal tags bytes into a tag slice: %w", err)
	}

	return config, nil
}

// GetOpenStores returns all currently open stores.
func (f *FormattedProvider) GetOpenStores() []spi.Store {
	openStores := make([]spi.Store, len(f.openStores))

	var counter int

	f.lock.RLock()
	defer f.lock.RUnlock()

	for _, openStore := range f.openStores {
		openStores[counter] = openStore
		counter++
	}

	return openStores
}

// Close closes all stores created under this store provider.
// For persistent store implementations, this does not delete any data in the underlying stores.
func (f *FormattedProvider) Close() error {
	err := f.provider.Close()
	if err != nil {
		return fmt.Errorf("failed to close underlying provider: %w", err)
	}

	return nil
}

func (f *FormattedProvider) storeStoreConfig(storeName string, configBytes []byte) error {
	store, err := f.openStore(storeName + "_formattedstore_storeconfig")
	if err != nil {
		return fmt.Errorf("failed to open the store config store: %w", err)
	}

	err = store.Put("formattedstore_storeconfig", configBytes)
	if err != nil {
		return fmt.Errorf("failed to store config bytes in the store config store: %w", err)
	}

	return nil
}

func (f *FormattedProvider) openStore(name string) (*formatStore, error) {
	openStore, ok := f.openStores[name]
	if !ok {
		store, err := f.provider.OpenStore(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open store in underlying provider: %w", err)
		}

		newFormatStore := formatStore{
			name:            name,
			underlyingStore: store,
			formatter:       f.formatter,
			close:           f.removeStore,
		}

		f.openStores[name] = &newFormatStore

		return &newFormatStore, nil
	}

	return openStore, nil
}

func (f *FormattedProvider) removeStore(name string) {
	f.lock.Lock()
	defer f.lock.Unlock()

	delete(f.openStores, name)
}

type formatStore struct {
	name            string
	underlyingStore spi.Store
	formatter       Formatter
	close           closer
	lock            sync.RWMutex
}

// If using a formatter with non-deterministic key formatting, then the store configuration must be set prior to calling
// this method, since it sets up a special "key" tag that's used to enable data retrieval.
// TODO (#2666): automatically set store configuration.
func (f *formatStore) Put(key string, value []byte, tags ...spi.Tag) error {
	errInputValidation := validatePutInput(key, value, tags)
	if errInputValidation != nil {
		return errInputValidation
	}

	if f.formatter.UsesDeterministicKeyFormatting() {
		err := f.formatAndPut(key, value, tags)
		if err != nil {
			return fmt.Errorf("failed to format and put data: %w", err)
		}

		return nil
	}

	err := f.storeUsingNonDeterministicKey(key, value, tags)
	if err != nil {
		return fmt.Errorf("failed to store data using non-deterministic key formatting: %w", err)
	}

	return nil
}

func (f *formatStore) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	if f.formatter.UsesDeterministicKeyFormatting() {
		value, err := f.getValueStoredUnderDeterministicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get value stored under deterministically generated key: %w", err)
		}

		return value, nil
	}

	value, err := f.lockAndGetValueStoredUnderNonDeterministicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get value stored under non-deterministically generated key: %w", err)
	}

	return value, nil
}

func (f *formatStore) GetTags(key string) ([]spi.Tag, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	if f.formatter.UsesDeterministicKeyFormatting() {
		tags, err := f.getTagsStoredUnderDeterministicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get tags stored under deterministically generated key: %w", err)
		}

		return tags, nil
	}

	tags, err := f.getTagsStoredUnderNonDeterministicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags stored under non-deterministically generated key: %w", err)
	}

	return tags, nil
}

func (f *formatStore) GetBulk(keys ...string) ([][]byte, error) {
	errInputValidation := ensureNoEmptyKeys(keys)
	if errInputValidation != nil {
		return nil, errInputValidation
	}

	if f.formatter.UsesDeterministicKeyFormatting() {
		values, err := f.getValuesStoredUnderDeterministicKeys(keys)
		if err != nil {
			return nil, fmt.Errorf("failed to get values stored under deterministically generated keys: %w", err)
		}

		return values, nil
	}

	values, err := f.getValuesStoredUnderNonDeterministicKeys(keys)
	if err != nil {
		return nil, fmt.Errorf("failed to get values stored under non-deterministically generated keys: %w", err)
	}

	return values, nil
}

func (f *formatStore) Query(expression string, options ...spi.QueryOption) (spi.Iterator, error) {
	if expression == "" {
		return nil, errInvalidQueryExpressionFormat
	}

	expressionSplit := strings.Split(expression, ":")
	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		_, _, formattedTags, err := f.formatter.Format("", nil, spi.Tag{Name: expressionSplit[0]})
		if err != nil {
			return nil, fmt.Errorf(failFormat, "tag name", expressionSplit[0], err)
		}

		underlyingIterator, err := f.underlyingStore.Query(formattedTags[0].Name, options...)
		if err != nil {
			return nil, fmt.Errorf(failQueryUnderlyingStore, err)
		}

		return &formattedIterator{underlyingIterator: underlyingIterator, formatter: f.formatter}, nil
	case expressionTagNameAndValueLength:
		_, _, formattedTags, err := f.formatter.Format("", nil,
			spi.Tag{Name: expressionSplit[0], Value: expressionSplit[1]})
		if err != nil {
			return nil, fmt.Errorf("failed to format tag: %w", err)
		}

		underlyingIterator, err := f.underlyingStore.Query(
			fmt.Sprintf("%s:%s", formattedTags[0].Name, formattedTags[0].Value), options...)
		if err != nil {
			return nil, fmt.Errorf(failQueryUnderlyingStore, err)
		}

		return &formattedIterator{underlyingIterator: underlyingIterator, formatter: f.formatter}, nil
	default:
		return nil, errInvalidQueryExpressionFormat
	}
}

func (f *formatStore) Delete(key string) error {
	if key == "" {
		return errEmptyKey
	}

	if f.formatter.UsesDeterministicKeyFormatting() {
		err := f.deleteDataStoredUnderDeterministicKey(key)
		if err != nil {
			return fmt.Errorf("failed to delete data stored under deterministic key: %w", err)
		}

		return nil
	}

	err := f.deleteDataStoredUnderNonDeterministicKey(key)
	if err != nil {
		return fmt.Errorf("failed to delete data stored under non-deterministic key: %w", err)
	}

	return nil
}

func (f *formatStore) Batch(operations []spi.Operation) error {
	for _, operation := range operations {
		if operation.Key == "" {
			return errEmptyKey
		}
	}

	var formattedOperations []spi.Operation

	var err error

	if f.formatter.UsesDeterministicKeyFormatting() {
		formattedOperations, err = f.generateFormattedOperationsUsingDeterministicKeys(operations)
		if err != nil {
			return fmt.Errorf("failed to generate formatted operations using deterministic keys: %w", err)
		}
	} else {
		f.lock.Lock()
		defer f.lock.Unlock()

		formattedOperations, err = f.generateFormattedOperationsUsingNonDeterministicKeys(operations)
		if err != nil {
			return fmt.Errorf("failed to generate formatted operations using non-deterministic keys: %w", err)
		}
	}

	err = f.underlyingStore.Batch(formattedOperations)
	if err != nil {
		return fmt.Errorf("failed to perform formatted operations in underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) Flush() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	err := f.underlyingStore.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) Close() error {
	f.close(f.name)

	err := f.underlyingStore.Close()
	if err != nil {
		return fmt.Errorf("failed to close underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) storeUsingNonDeterministicKey(key string, value []byte, tags []spi.Tag) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	iterator, err := f.queryUsingKeyTag(key)
	if err != nil {
		return fmt.Errorf("failed to query using the key tag: %w", err)
	}

	atLeastOneReturnedValue, err := iterator.Next()
	if err != nil {
		return fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	tags = append(tags, generateKeyTag(key))

	if !atLeastOneReturnedValue {
		// This is a new value, so there is no previous key to use. Must generate a new one.
		errFormatAndPut := f.formatAndPut(key, value, tags)
		if errFormatAndPut != nil {
			return fmt.Errorf("failed to format and put data: %w", errFormatAndPut)
		}

		return nil
	}

	foundKey, err := iterator.Key()
	if err != nil {
		return fmt.Errorf("failed to get key from iterator: %w", err)
	}

	foundMoreMatchingKeys, err := iterator.Next()
	if err != nil {
		return fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	if foundMoreMatchingKeys {
		return fmt.Errorf("unexpectedly found multiple results matching query. Only one is expected")
	}

	_, formattedValue, formattedTags, err := f.formatter.Format(foundKey, value, tags...)
	if err != nil {
		return fmt.Errorf(failFormatData, err)
	}

	err = f.underlyingStore.Put(foundKey, formattedValue, formattedTags...)
	if err != nil {
		return fmt.Errorf("failed to put formatted data in underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) formatAndPut(key string, value []byte, tags []spi.Tag) error {
	formattedKey, formattedValue, formattedTags, err := f.formatter.Format(key, value, tags...)
	if err != nil {
		return fmt.Errorf(failFormatData, err)
	}

	err = f.underlyingStore.Put(formattedKey, formattedValue, formattedTags...)
	if err != nil {
		return fmt.Errorf("failed to put formatted data in underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) getValueStoredUnderDeterministicKey(key string) ([]byte, error) {
	formattedKey, _, _, err := f.formatter.Format(key, nil, nil...)
	if err != nil {
		return nil, fmt.Errorf(failFormat, "key", key, err)
	}

	formattedValue, err := f.underlyingStore.Get(formattedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted value from underlying store: %w", err)
	}

	_, value, _, err := f.formatter.Deformat("", formattedValue)
	if err != nil {
		return nil, fmt.Errorf(failDeformat, "value", string(formattedValue), err)
	}

	return value, nil
}

func (f *formatStore) lockAndGetValueStoredUnderNonDeterministicKey(key string) ([]byte, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.getValueStoredUnderNonDeterministicKey(key)
}

func (f *formatStore) getValueStoredUnderNonDeterministicKey(key string) ([]byte, error) {
	// Base64 encode in order to transform any ':' characters, since ':' is a special character in a query expression.
	iterator, err := f.Query("Key:" + base64.StdEncoding.EncodeToString([]byte(key)))
	if err != nil {
		return nil, fmt.Errorf("failed to query store: %w", err)
	}

	atLeastOneReturnedValue, err := iterator.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	if !atLeastOneReturnedValue {
		return nil, spi.ErrDataNotFound
	}

	foundValue, err := iterator.Value()
	if err != nil {
		return nil, fmt.Errorf("failed to get value from iterator: %w", err)
	}

	foundMoreMatchingValues, err := iterator.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	if foundMoreMatchingValues {
		return nil, fmt.Errorf("unexpectedly found multiple results matching query. Only one is expected")
	}

	return foundValue, nil
}

func (f *formatStore) getTagsStoredUnderDeterministicKey(key string) ([]spi.Tag, error) {
	formattedKey, _, _, err := f.formatter.Format(key, nil)
	if err != nil {
		return nil, fmt.Errorf(failFormat, "key", key, err)
	}

	formattedTags, err := f.underlyingStore.GetTags(formattedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted tags from underlying store: %w", err)
	}

	// FormatProvider must support EDV formatting, and EDV tags are not reversible since they are hashed.
	// Retrieving EDV tags requires embedding them in the stored value itself.
	// In order to support this use case, formatStore also calls the underlying store's Get method.
	formattedValue, err := f.underlyingStore.Get(formattedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted tags from underlying store: %w", err)
	}

	_, _, tags, err := f.formatter.Deformat("", formattedValue, formattedTags...)
	if err != nil {
		return nil, fmt.Errorf("failed to deformat tags: %w", err)
	}

	return tags, nil
}

func (f *formatStore) getTagsStoredUnderNonDeterministicKey(key string) ([]spi.Tag, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	// Base64 encode in order to transform any ':' characters, since ':' is a special character in a query expression.
	iterator, err := f.Query(keyTagName + ":" + base64.StdEncoding.EncodeToString([]byte(key)))
	if err != nil {
		return nil, fmt.Errorf("failed to query store: %w", err)
	}

	atLeastOneReturnedValue, err := iterator.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	if !atLeastOneReturnedValue {
		return nil, spi.ErrDataNotFound
	}

	foundTags, err := iterator.Tags()
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from iterator: %w", err)
	}

	foundMoreMatchingResults, err := iterator.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	if foundMoreMatchingResults {
		return nil, fmt.Errorf("unexpectedly found multiple results matching query. Only one is expected")
	}

	return filterOutKeyTag(foundTags, base64.StdEncoding.EncodeToString([]byte(key))), nil
}

func (f *formatStore) getValuesStoredUnderDeterministicKeys(keys []string) ([][]byte, error) {
	formattedKeys := make([]string, len(keys))

	for i, key := range keys {
		var err error

		formattedKeys[i], _, _, err = f.formatter.Format(key, nil)
		if err != nil {
			return nil, fmt.Errorf(failFormat, "key", key, err)
		}
	}

	formattedValues, err := f.underlyingStore.GetBulk(formattedKeys...)
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted values from underlying store: %w", err)
	}

	deformattedValues := make([][]byte, len(formattedValues))

	for i, formattedValue := range formattedValues {
		if formattedValue != nil {
			_, deformattedValue, _, err := f.formatter.Deformat("", formattedValue, nil...)
			if err != nil {
				return nil, fmt.Errorf(failDeformat, "value", formattedValue, err)
			}

			deformattedValues[i] = deformattedValue
		}
	}

	return deformattedValues, nil
}

func (f *formatStore) getValuesStoredUnderNonDeterministicKeys(keys []string) ([][]byte, error) {
	retrievedValues := make([][]byte, len(keys))

	f.lock.RLock()
	defer f.lock.RUnlock()

	for i, key := range keys {
		value, err := f.getValueStoredUnderNonDeterministicKey(key)
		if err != nil && !errors.Is(err, spi.ErrDataNotFound) {
			return nil, fmt.Errorf("unexpected failure while attempting to retrieve value: %w", err)
		}

		retrievedValues[i] = value
	}

	return retrievedValues, nil
}

func (f *formatStore) deleteDataStoredUnderDeterministicKey(key string) error {
	formattedKey, _, _, err := f.formatter.Format(key, nil, nil...)
	if err != nil {
		return fmt.Errorf(failFormat, "key", key, err)
	}

	err = f.underlyingStore.Delete(formattedKey)
	if err != nil {
		return fmt.Errorf("failed to delete data in underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) deleteDataStoredUnderNonDeterministicKey(key string) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	iterator, err := f.queryUsingKeyTag(key)
	if err != nil {
		return fmt.Errorf("failed to query using the key tag: %w", err)
	}

	atLeastOneReturnedValue, err := iterator.Next()
	if err != nil {
		return fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	if !atLeastOneReturnedValue {
		return nil
	}

	foundKey, err := iterator.Key()
	if err != nil {
		return fmt.Errorf("failed to get key from iterator: %w", err)
	}

	foundMoreMatchingKeys, err := iterator.Next()
	if err != nil {
		return fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	if foundMoreMatchingKeys {
		return fmt.Errorf("unexpectedly found multiple results matching query. Only one is expected")
	}

	err = f.underlyingStore.Delete(foundKey)
	if err != nil {
		return fmt.Errorf("failed to delete data in underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) generateFormattedOperationsUsingDeterministicKeys(
	operations []spi.Operation) ([]spi.Operation, error) {
	formattedOperations := make([]spi.Operation, len(operations))

	for i, operation := range operations {
		formattedKey, formattedValue, formattedTags, err :=
			f.formatter.Format(operation.Key, operation.Value, operation.Tags...)
		if err != nil {
			return nil, fmt.Errorf(failFormatData, err)
		}

		if operation.Value == nil {
			// Ensure that, even if the formatter output a non-nil value,
			// the "nil value = delete" semantics defined in spi.Store are followed.
			formattedOperations[i] = spi.Operation{
				Key:  formattedKey,
				Tags: formattedTags,
			}

			continue
		}

		formattedOperations[i] = spi.Operation{
			Key:   formattedKey,
			Value: formattedValue,
			Tags:  formattedTags,
		}
	}

	return formattedOperations, nil
}

func (f *formatStore) generateFormattedOperationsUsingNonDeterministicKeys(
	operations []spi.Operation) ([]spi.Operation, error) {
	var formattedOperations []spi.Operation

	resolvedKeys := make(map[string]string, len(operations))

	for _, operation := range operations {
		if operation.Value == nil {
			deleteOperation, err := f.createFormattedDeleteOperation(resolvedKeys, operation)
			if err != nil {
				return nil, fmt.Errorf("failed to prepare formatted delete operation: %w", err)
			}

			// An empty key in the returned operation means that it's not needed or is redundant with another delete operation.
			if deleteOperation.Key != "" {
				formattedOperations = append(formattedOperations, deleteOperation)
			}
		} else {
			putOperation, err := f.createFormattedPutOperation(resolvedKeys, operation)
			if err != nil {
				return nil, fmt.Errorf("failed to prepare formatted put operation: %w", err)
			}

			formattedOperations = append(formattedOperations, putOperation)
		}
	}

	return formattedOperations, nil
}

func (f *formatStore) createFormattedDeleteOperation(resolvedKeys map[string]string,
	operation spi.Operation) (spi.Operation, error) {
	// We must determine which formatted key to use. There are two cases to consider:
	// 1. First, check the resolvedKeys slice. It contains the formatted keys used in previous put operations within
	//    this batch. If the key is found, then we must use that formatted key in order to ensure consistency.
	// 2. If the resolvedKeys slice doesn't have the formatted key, then we have to query the store. If
	//    a value is found, then we have the formatted key we must use. If no value is found, then that means
	//    that this key was never stored, and since we know none of the prior operations store this key
	//    either, then that means that there's nothing to do here, so this delete operation is dropped.
	formattedKey, err := f.determineFormattedKeyToUse(resolvedKeys, operation.Key)
	if err != nil {
		return spi.Operation{}, fmt.Errorf("unexpected failure while determining formatted key to use: %w", err)
	}

	// If the formatted key wasn't found, or is already being deleted (is blank either way),
	// then there's nothing to delete, and so this operation is not needed.
	if formattedKey != "" {
		// In the event that a user does a Put, Delete, Put within the same batch, all with the same key, then we
		// should make sure that second Put uses a fresh non-deterministically generated formatted key.
		// This is in order to be consistent with what would normally happen when doing a Put after a Delete in a
		// non-batch call. The key is mapped to a blank formatted string below, which is used to indicate that
		// a new formatted key should be generated in any subsequent Put operations for the same key within this batch.
		resolvedKeys[operation.Key] = ""

		return spi.Operation{Key: formattedKey}, nil
	}

	// This empty operation will be dropped in the parent method.
	return spi.Operation{}, nil
}

func (f *formatStore) createFormattedPutOperation(resolvedKeys map[string]string,
	operation spi.Operation) (spi.Operation, error) {
	formattedKey, err := f.determineFormattedKeyToUse(resolvedKeys, operation.Key)
	if err != nil {
		return spi.Operation{}, fmt.Errorf("unexpected failure while determining formatted key to use: %w", err)
	}

	tagsToFormat := generateTagsToFormat(operation)

	var putOperation spi.Operation

	if formattedKey == "" {
		putOperation, err = f.createFormattedPutOperationUsingNewFormattedKey(resolvedKeys, operation, tagsToFormat)
		if err != nil {
			return spi.Operation{}, fmt.Errorf("failed to prepare formatted put operation using non-previously-resolved "+
				"formatted key: %w", err)
		}
	} else {
		putOperation, err = f.createFormattedPutOperationUsingExistingFormattedKey(resolvedKeys, formattedKey,
			operation, tagsToFormat)
		if err != nil {
			return spi.Operation{}, fmt.Errorf("failed to prepare formatted put operation using previously-resolved "+
				"formatted key: %w", err)
		}
	}

	return putOperation, nil
}

func (f *formatStore) determineFormattedKeyToUse(resolvedKeys map[string]string,
	currentOperationKey string) (string, error) {
	// There are several cases to consider:
	// 1. First, check the resolvedKeys slice. It contains the formatted keys used in previous put operations within
	//	  this batch. If the key if found then we must use that formatted key in order to ensure we don't create
	//    duplicates in the database. If a formatted key is found in the map but it's set to a blank string,
	//    then we know from the createFormattedDeleteOperation method that this formatted key has been effectively
	//    marked for deletion and should not be reused.
	// 2. If the resolvedKeys slice doesn't have the formatted key and the key wasn't previously marked for deletion,
	//    then we have to query the store. If a value is found, then that means that we must use that existing
	//    formatted key for whichever operation is calling this method.
	// 3. If the formatted key was marked for deletion, then we should not query the store. In the case of a Put,
	//    we want to make sure that a fresh non-deterministically formatted key gets generated instead of reusing the
	//    old one in order to be consistent with the equivalent non-batched operations.
	//    In the case of a Delete, the query is simply unnecessary.
	formattedKeyToUse, isMarkedForDeletion := getFormattedKeyFromPreviouslyResolvedKeys(resolvedKeys, currentOperationKey)

	// If we haven't determined the formatted key yet, then we must query the store. If the formatted key still
	// can't be found, then it must not exist.
	if formattedKeyToUse == "" && !isMarkedForDeletion {
		var err error

		formattedKeyToUse, err = f.getFormattedKeyViaStoreQuery(currentOperationKey)
		if err != nil {
			return "", fmt.Errorf("unexpected failure while attempting to "+
				"determine formatted key via store query: %w", err)
		}
	}

	return formattedKeyToUse, nil
}

func (f *formatStore) createFormattedPutOperationUsingNewFormattedKey(resolvedKeys map[string]string,
	operation spi.Operation, tagsToFormat []spi.Tag) (spi.Operation, error) {
	// This is a new value, so there is no previous key to use. Must generate a new one.
	formattedKey, formattedValue, formattedTags, err :=
		f.formatter.Format(operation.Key, operation.Value, tagsToFormat...)
	if err != nil {
		return spi.Operation{}, fmt.Errorf(failFormatData, err)
	}

	resolvedKeys[operation.Key] = formattedKey

	return spi.Operation{
		Key:   formattedKey,
		Value: formattedValue,
		Tags:  formattedTags,
	}, nil
}

func (f *formatStore) createFormattedPutOperationUsingExistingFormattedKey(resolvedKeys map[string]string,
	formattedKey string, operation spi.Operation, tagsToFormat []spi.Tag) (spi.Operation, error) {
	_, formattedValue, formattedTags, err :=
		f.formatter.Format(formattedKey, operation.Value, tagsToFormat...)
	if err != nil {
		return spi.Operation{}, fmt.Errorf(failFormatData, err)
	}

	resolvedKeys[operation.Key] = formattedKey

	return spi.Operation{
		Key:   formattedKey,
		Value: formattedValue,
		Tags:  formattedTags,
	}, nil
}

func (f *formatStore) getFormattedKeyViaStoreQuery(key string) (string, error) {
	iterator, err := f.queryUsingKeyTag(key)
	if err != nil {
		return "", fmt.Errorf("failed to query using the key tag: %w", err)
	}

	atLeastOneReturnedValue, err := iterator.Next()
	if err != nil {
		return "", fmt.Errorf("failed to get next result from iterator: %w", err)
	}

	if atLeastOneReturnedValue {
		formattedKeyToUse, err := iterator.Key()
		if err != nil {
			return "", fmt.Errorf("failed to get key from iterator: %w", err)
		}

		foundMoreMatchingKeys, err := iterator.Next()
		if err != nil {
			return "", fmt.Errorf("failed to get next result from iterator: %w", err)
		}

		if foundMoreMatchingKeys {
			return "", fmt.Errorf("unexpectedly found multiple results matching query. Only one is expected")
		}

		return formattedKeyToUse, nil
	}

	return "", nil
}

func (f *formatStore) queryUsingKeyTag(key string) (spi.Iterator, error) {
	// Base64 encode in order to transform any ':' characters, since ':' is a special character in a query expression.
	_, _, formattedTags, err := f.formatter.Format("", nil,
		generateKeyTag(key))
	if err != nil {
		return nil, fmt.Errorf("failed to format tag: %w", err)
	}

	iterator, err := f.underlyingStore.Query(
		fmt.Sprintf("%s:%s", formattedTags[0].Name, formattedTags[0].Value))
	if err != nil {
		return nil, fmt.Errorf(failQueryUnderlyingStore, err)
	}

	return iterator, nil
}

type formattedIterator struct {
	underlyingIterator spi.Iterator
	formatter          Formatter
}

func (f *formattedIterator) Next() (bool, error) {
	nextOK, err := f.underlyingIterator.Next()
	if err != nil {
		return false, fmt.Errorf("failed to move the entry pointer in the underlying iterator: %w", err)
	}

	return nextOK, nil
}

func (f *formattedIterator) Key() (string, error) {
	formattedKey, err := f.underlyingIterator.Key()
	if err != nil {
		return "", fmt.Errorf("failed to get formatted key from the underlying iterator: %w", err)
	}

	// Some Formatter implementations (like EDV Encrypted Formatter) require the value to determine the deformatted key.
	formattedValue, err := f.underlyingIterator.Value()
	if err != nil {
		return "", fmt.Errorf(failGetValueUnderlyingIterator, err)
	}

	key, _, _, err := f.formatter.Deformat(formattedKey, formattedValue, nil...)
	if err != nil {
		return "", fmt.Errorf("failed to deformat formatted key from the underlying iterator: %w", err)
	}

	return key, nil
}

func (f *formattedIterator) Value() ([]byte, error) {
	formattedValue, err := f.underlyingIterator.Value()
	if err != nil {
		return nil, fmt.Errorf(failGetValueUnderlyingIterator, err)
	}

	_, value, _, err := f.formatter.Deformat("", formattedValue)
	if err != nil {
		return nil, fmt.Errorf(failDeformat, "value", string(formattedValue), err)
	}

	return value, nil
}

func (f *formattedIterator) Tags() ([]spi.Tag, error) {
	formattedTags, err := f.underlyingIterator.Tags()
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted tags from the underlying iterator: %w", err)
	}

	// FormatProvider must support EDV formatting, and EDV tags are not reversible since they are hashed.
	// Retrieving EDV tags requires embedding them in the stored value itself.
	// In order to support this use case, formatStore calls the underlying iterator's Value method as well.
	formattedValue, err := f.underlyingIterator.Value()
	if err != nil {
		return nil, fmt.Errorf(failGetValueUnderlyingIterator, err)
	}

	if f.formatter.UsesDeterministicKeyFormatting() {
		_, _, tags, errDeformat := f.formatter.Deformat("", formattedValue, formattedTags...)
		if errDeformat != nil {
			return nil, fmt.Errorf(failDeformat, "value", string(formattedValue), err)
		}

		return tags, nil
	}

	formattedKey, err := f.underlyingIterator.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted key from the underlying iterator: %w", err)
	}

	key, _, tags, err := f.formatter.Deformat(formattedKey, formattedValue, formattedTags...)
	if err != nil {
		return nil, fmt.Errorf(failDeformat, "value", string(formattedValue), err)
	}

	return filterOutKeyTag(tags, base64.StdEncoding.EncodeToString([]byte(key))), nil
}

func (f *formattedIterator) TotalItems() (int, error) {
	return f.underlyingIterator.TotalItems()
}

func (f *formattedIterator) Close() error {
	err := f.underlyingIterator.Close()
	if err != nil {
		return fmt.Errorf("failed to close underlying iterator: %w", err)
	}

	return nil
}

func validatePutInput(key string, value []byte, tags []spi.Tag) error {
	if key == "" {
		return errEmptyKey
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	for _, tag := range tags {
		if strings.Contains(tag.Name, ":") {
			return fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, ":") {
			return fmt.Errorf(invalidTagValue, tag.Value)
		}
	}

	return nil
}

func ensureNoEmptyKeys(keys []string) error {
	if len(keys) == 0 {
		return errors.New("keys slice must contain at least one key")
	}

	for _, key := range keys {
		if key == "" {
			return errEmptyKey
		}
	}

	return nil
}

func generateKeyTag(key string) spi.Tag {
	// Base64 encode the key in order to transform any ':' characters, since we need to do a query later for this key
	// and ':' is a special character in a query expression.
	return spi.Tag{Name: keyTagName, Value: base64.StdEncoding.EncodeToString([]byte(key))}
}

func filterOutKeyTag(tags []spi.Tag, tagValueToFilterOut string) []spi.Tag {
	var filteredTags []spi.Tag

	for _, tag := range tags {
		if !(tag.Name == keyTagName && tag.Value == tagValueToFilterOut) {
			filteredTags = append(filteredTags, tag)
		}
	}

	return filteredTags
}

func getFormattedKeyFromPreviouslyResolvedKeys(resolvedKeys map[string]string,
	key string) (formattedKeyToUse string, isMarkedForDeletion bool) {
	for unformattedKey, formattedKey := range resolvedKeys {
		if unformattedKey == key {
			formattedKeyToUse = formattedKey

			if formattedKey == "" {
				isMarkedForDeletion = true
			}

			break
		}
	}

	return formattedKeyToUse, isMarkedForDeletion
}

func generateTagsToFormat(operation spi.Operation) []spi.Tag {
	tagsToFormat := make([]spi.Tag, len(operation.Tags)+1)

	for j, tag := range operation.Tags {
		tagsToFormat[j] = tag
	}

	tagsToFormat[len(tagsToFormat)-1] = generateKeyTag(operation.Key)

	return tagsToFormat
}
