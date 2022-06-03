/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	criterionTagNameOnlyLength     = 1
	criterionTagNameAndValueLength = 2

	invalidTagName  = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue = `"%s" is an invalid tag value since it contains one or more ':' characters`
)

var (
	errEmptyKey                     = errors.New("key cannot be empty")
	errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
		"it must be in the following format: " +
		"[Criterion1][Operator][Criterion2][Operator]...[CriterionN] (without square brackets)")
)

// RESTProviderOption allows for configuration of a RESTProvider.
type RESTProviderOption func(opts *RESTProvider)

// WithTLSConfig is an option that allows for the definition of a secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) RESTProviderOption {
	return func(opts *RESTProvider) {
		opts.restClient.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}

// WithHeaders option is for setting additional http request headers (since it's a function, it can call a remote
// authorization server to fetch the necessary info needed in these headers).
func WithHeaders(addHeadersFunc addHeaders) RESTProviderOption {
	return func(opts *RESTProvider) {
		opts.restClient.headersFunc = addHeadersFunc
	}
}

// WithFullDocumentsReturnedFromQueries option is a performance optimization that speeds up queries by getting
// full documents from the EDV server instead of only document locations - each of which would require a separate REST
// call to retrieve. The EDV server that this RESTProvider connects to must support the TrustBloc EDV server extension
// as defined here: https://github.com/trustbloc/edv/blob/main/docs/extensions.md#return-full-documents-on-query.
func WithFullDocumentsReturnedFromQueries() RESTProviderOption {
	return func(restProvider *RESTProvider) {
		restProvider.returnFullDocumentsOnQuery = true
	}
}

// WithBatchEndpointExtension option is a performance optimization that allows for restStore.Batch to only require one
// REST call. The EDV server that this RESTProvider connects to must support the TrustBloc EDV server extension
// as defined here: https://github.com/trustbloc/edv/blob/main/docs/extensions.md#batch-endpoint.
func WithBatchEndpointExtension() RESTProviderOption {
	return func(opts *RESTProvider) {
		opts.batchEndpointExtensionEnabled = true
	}
}

// RESTProvider is a spi.Provider that can be used to store data in a server supporting the
// data vault HTTP API as defined in https://identity.foundation/confidential-storage/#http-api.
type RESTProvider struct {
	vaultID    string
	formatter  *EncryptedFormatter
	restClient *restClient
	openStores map[string]*restStore
	lock       sync.RWMutex

	returnFullDocumentsOnQuery    bool
	batchEndpointExtensionEnabled bool
}

// NewRESTProvider returns a new RESTProvider. edvServerURL is the base URL for the EDV server.
// vaultID is the ID of the vault where this provider will store data. The vault must be created in advance, and since
// the EDV REST API does not provide a method to check if a vault with a given ID exists, any errors due to a
// non-existent vault will be deferred until calls are actually made to it in the store.
func NewRESTProvider(edvServerURL, vaultID string, formatter *EncryptedFormatter,
	options ...RESTProviderOption) *RESTProvider {
	client := restClient{
		edvServerURL: edvServerURL,
		httpClient:   &http.Client{},
	}

	restProvider := RESTProvider{
		vaultID:    vaultID,
		formatter:  formatter,
		restClient: &client,
		openStores: make(map[string]*restStore),
	}

	for _, opt := range options {
		opt(&restProvider)
	}

	return &restProvider
}

type closer func(storeName string)

// OpenStore opens a new RESTStore, using name as the namespace.
func (r *RESTProvider) OpenStore(name string) (spi.Store, error) {
	if name == "" {
		return nil, fmt.Errorf("store name cannot be empty")
	}

	storeName := strings.ToLower(name)

	r.lock.Lock()
	defer r.lock.Unlock()

	openStore := r.openStores[storeName]
	if openStore == nil {
		newStore := &restStore{
			vaultID:                       r.vaultID,
			name:                          storeName,
			formatter:                     r.formatter,
			restClient:                    r.restClient,
			returnFullDocumentsOnQuery:    r.returnFullDocumentsOnQuery,
			batchEndpointExtensionEnabled: r.batchEndpointExtensionEnabled,
			close:                         r.removeStore,
		}
		r.openStores[storeName] = newStore

		return newStore, nil
	}

	return openStore, nil
}

// SetStoreConfig isn't needed for EDV storage, since indexes are managed by the server automatically based on the
// tags used in values. This method simply stores the configuration in memory so that it can be retrieved later
// via the GetStoreConfig method, which allows it to be more consistent with how other store implementations work.
// TODO (#2492) Store store config in persistent EDV storage for true consistency with other store implementations.
func (r *RESTProvider) SetStoreConfig(name string, config spi.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	name = strings.ToLower(name)

	openStore, ok := r.openStores[name]
	if !ok {
		return spi.ErrStoreNotFound
	}

	openStore.config = config

	return nil
}

// GetStoreConfig returns the store configuration currently stored in memory.
func (r *RESTProvider) GetStoreConfig(name string) (spi.StoreConfiguration, error) {
	name = strings.ToLower(name)

	openStore, ok := r.openStores[name]
	if !ok {
		return spi.StoreConfiguration{}, spi.ErrStoreNotFound
	}

	return openStore.config, nil
}

// GetOpenStores returns all currently open stores.
func (r *RESTProvider) GetOpenStores() []spi.Store {
	r.lock.RLock()
	defer r.lock.RUnlock()

	openStores := make([]spi.Store, len(r.openStores))

	var counter int

	for _, db := range r.openStores {
		openStores[counter] = db
		counter++
	}

	return openStores
}

// Close always returns a nil error since there's nothing to close for a RESTProvider.
func (r *RESTProvider) Close() error {
	return nil
}

func (r *RESTProvider) removeStore(name string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	_, ok := r.openStores[name]
	if ok {
		delete(r.openStores, name)
	}
}

// restStore is a store for storing EDV documents via the REST API.
type restStore struct {
	vaultID                       string
	name                          string
	formatter                     *EncryptedFormatter
	restClient                    *restClient
	config                        spi.StoreConfiguration
	returnFullDocumentsOnQuery    bool
	batchEndpointExtensionEnabled bool
	close                         closer
	lock                          sync.RWMutex
}

// Put stores data into an EDV server.
func (r *restStore) Put(key string, value []byte, tags ...spi.Tag) error {
	errInputValidation := validatePutInput(key, value, tags)
	if errInputValidation != nil {
		return errInputValidation
	}

	if r.formatter.UsesDeterministicKeyFormatting() {
		err := r.putUsingDeterministicDocumentID(key, value, tags)
		if err != nil {
			return fmt.Errorf("failed to store data using a deterministic document ID: %w", err)
		}
	} else {
		err := r.appendKeyTagThenLockAndPutUsingRandomDocumentID(key, value, tags)
		if err != nil {
			return fmt.Errorf("failed to store data using a random document ID: %w", err)
		}
	}

	return nil
}

func (r *restStore) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	var encryptedDocumentBytes []byte

	var err error

	if r.formatter.UsesDeterministicKeyFormatting() {
		encryptedDocumentBytes, err = r.getEncryptedDocumentStoredUnderDeterministicID(key)
		if err != nil {
			return nil,
				fmt.Errorf("failed to get encrypted document stored under a deterministic document ID: %w", err)
		}
	} else {
		encryptedDocumentBytes, err = r.getEncryptedDocumentStoredUnderRandomID(key)
		if err != nil {
			return nil,
				fmt.Errorf("failed to get encrypted document stored under a randomly-generated ID: %w", err)
		}
	}

	_, value, _, err := r.formatter.Deformat("", encryptedDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt encrypted document: %w", err)
	}

	return value, nil
}

func (r *restStore) GetTags(key string) ([]spi.Tag, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	var encryptedDocumentBytes []byte

	var err error

	if r.formatter.UsesDeterministicKeyFormatting() {
		encryptedDocumentBytes, err = r.getEncryptedDocumentStoredUnderDeterministicID(key)
		if err != nil {
			return nil,
				fmt.Errorf("failed to get encrypted document stored under a deterministic document ID: %w", err)
		}
	} else {
		encryptedDocumentBytes, err = r.getEncryptedDocumentStoredUnderRandomID(key)
		if err != nil {
			return nil,
				fmt.Errorf("failed to get encrypted document stored under a randomly-generated ID: %w", err)
		}
	}

	_, _, tags, err := r.formatter.Deformat("", encryptedDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt encrypted document: %w", err)
	}

	if !r.formatter.UsesDeterministicKeyFormatting() {
		tags = filterOutKeyTag(tags, key)
	}

	return tags, nil
}

// EDV doesn't support getting documents in bulk, so the best we can do is emulate it by doing a Get on each
// key. A more efficient way to get documents in bulk is to use tags and querying with the "return full documents
// on query" extension enabled, which is non-standard (as of writing).
func (r *restStore) GetBulk(keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys slice must contain at least one key")
	}

	values := make([][]byte, len(keys))

	r.lock.Lock()
	defer r.lock.Unlock()

	for i, key := range keys {
		var err error

		values[i], err = r.Get(key)
		if err != nil && !errors.Is(err, spi.ErrDataNotFound) {
			return nil, fmt.Errorf(`unexpected failure while getting value for key "%s": %w`, key, err)
		}
	}

	return values, nil
}

// Expression format: [Criterion1][Operator][Criterion2][Operator]...[CriterionN]. Square brackets are used here for
// visual clarity. Omit them from the actual expression string.
// Each Criterion can be in one of either two formats: Either "TagName" or "TagName:TagValue" (without quotes).
// If only using TagName, then the tag value will be treated as a wildcard, so any data tagged with the given TagName
// will be matched regardless of tag value. There must be at least one Criterion in the expression.
// Each operator must be either "&&" or "||" (without quotes). "&&" indicates an AND operator while "||"
// indicates an OR operator. For AND operations, tag names must be unique. e.g. TagName1:TagValue1&&TagName1:TagValue2
// will not work - the second criterion will overwrite the first. The order of operations are ANDs followed by ORs.
// Note that EDV doesn't support sorting or pagination.
// spi.WithPageSize will simply be ignored since it only relates to performance and not the actual end result.
// spi.WithInitialPageNum and spi.WithSortOrder will result in an error being returned since those options do
// affect the results that the Iterator returns.
func (r *restStore) Query(expression string, options ...spi.QueryOption) (spi.Iterator, error) {
	err := checkForUnsupportedQueryOptions(options)
	if err != nil {
		return nil, err
	}

	edvQuery, err := r.generateEDVQuery(expression)
	if err != nil {
		return nil, err
	}

	return r.query(edvQuery)
}

func (r *restStore) Delete(key string) error {
	if key == "" {
		return errEmptyKey
	}

	if r.formatter.UsesDeterministicKeyFormatting() {
		err := r.deleteDocumentUsingDeterministicID(key)
		if err != nil {
			return fmt.Errorf("failed to delete document using deterministic ID: %w", err)
		}
	} else {
		err := r.lockAndDeleteDocumentStoredUnderRandomID(key)
		if err != nil {
			return fmt.Errorf("failed to delete document using random ID: %w", err)
		}
	}

	return nil
}

// TODO (#2494): Return a spi.MultiError from here in the case of a failure.
func (r *restStore) Batch(operations []spi.Operation) error {
	if len(operations) == 0 {
		return errors.New("batch requires at least one operation")
	}

	for _, operation := range operations {
		if operation.Key == "" {
			return errEmptyKey
		}
	}

	if r.batchEndpointExtensionEnabled {
		err := r.fastBatchUsingBatchExtension(operations)
		if err != nil {
			return fmt.Errorf("failed to batch using batch extension: %w", err)
		}
	} else {
		// If the batch extension hasn't been enabled, we will have to emulate the behaviour using the
		// standard endpoints, which will be slower.
		err := r.slowBatchUsingStandardEndpoints(operations)
		if err != nil {
			return fmt.Errorf("failed to batch using standard endpoints: %w", err)
		}
	}

	return nil
}

func (r *restStore) Close() error {
	r.close(r.name)

	return nil
}

// restStore doesn't queue values, so there's never anything to flush.
func (r *restStore) Flush() error {
	return nil
}

func (r *restStore) putUsingDeterministicDocumentID(key string, value []byte, tags []spi.Tag) error {
	// If the batch endpoint extension is enabled, we can avoid the need to read the document first since the
	// batch endpoint does upserts instead of explicit creates and updates.
	if r.batchEndpointExtensionEnabled {
		err := r.storeUsingDeterministicDocumentIDAndBatchEndpoint(key, value, tags)
		if err != nil {
			return fmt.Errorf("failed to store document using "+
				"deterministic ID and batch endpoint: %w", err)
		}
	} else {
		err := r.storeUsingDeterministicDocumentIDAndStandardEndpoints(key, value, tags)
		if err != nil {
			return fmt.Errorf("failed to store document using random document ID and "+
				"standard endpoints: %w", err)
		}
	}

	return nil
}

func (r *restStore) appendKeyTagThenLockAndPutUsingRandomDocumentID(key string, value []byte, tags []spi.Tag) error {
	tags = append(tags, spi.Tag{Value: key})

	r.lock.Lock()
	defer r.lock.Unlock()

	return r.putUsingRandomDocumentID(key, value, tags)
}

func (r *restStore) storeUsingDeterministicDocumentIDAndBatchEndpoint(key string, value []byte, tags []spi.Tag) error {
	encryptedDocumentID, encryptedDocumentBytes, _, err :=
		r.formatter.format(r.name, key, value, tags...)
	if err != nil {
		return fmt.Errorf("failed to generate the encrypted document ID and "+
			"encrypted document bytes: %w", err)
	}

	err = r.restClient.batch(r.vaultID, []vaultOperation{{
		Operation:         upsertDocumentVaultOperation,
		DocumentID:        encryptedDocumentID,
		EncryptedDocument: encryptedDocumentBytes,
	}})
	if err != nil {
		return fmt.Errorf("failed to put data in EDV server via the batch endpoint "+
			"(is it enabled in the EDV server?): %w", err)
	}

	return nil
}

func (r *restStore) storeUsingDeterministicDocumentIDAndStandardEndpoints(
	key string, value []byte, tags []spi.Tag) error {
	documentID, err := r.formatter.generateDeterministicDocumentID(r.name, key)
	if err != nil {
		return fmt.Errorf("failed to generate the encrypted document ID: %w", err)
	}

	err = r.createOrUpdateDocumentBasedOnDeterministicDocumentID(key, documentID, value, tags)
	if err != nil {
		return fmt.Errorf("failed to create or update document based on document ID: %w", err)
	}

	return nil
}

func (r *restStore) createOrUpdateDocumentBasedOnDeterministicDocumentID(
	key, documentID string, value []byte, tags []spi.Tag) error {
	_, err := r.restClient.readDocument(r.vaultID, documentID)
	if err != nil {
		if errors.Is(err, spi.ErrDataNotFound) {
			err = r.formatTagsThenCreateDocument(key, documentID, value, tags)
			if err != nil {
				return fmt.Errorf("failed to format tags then create document: %w", err)
			}
		} else {
			return fmt.Errorf(`failed to determine if an EDV document for key "%s" in store "%s" already exists: %w`,
				key, r.name, err)
		}
	}

	err = r.updateDocument(key, documentID, value, tags)
	if err != nil {
		return fmt.Errorf("failed to update document: %w", err)
	}

	return nil
}

func (r *restStore) updateDocument(key, documentID string, value []byte, tags []spi.Tag) error {
	formattedTags, err := r.formatter.formatTags(r.name, tags)
	if err != nil {
		return fmt.Errorf("failed to format tags: %w", err)
	}

	encryptedDocumentBytes, err := r.formatter.formatValue(key, documentID, value, tags, formattedTags)
	if err != nil {
		return fmt.Errorf("failed to format value: %w", err)
	}

	err = r.restClient.updateDocument(r.vaultID, documentID, encryptedDocumentBytes)
	if err != nil {
		return fmt.Errorf("failed to update existing document in EDV server: %w", err)
	}

	return nil
}

func (r *restStore) getEncryptedDocumentStoredUnderDeterministicID(key string) ([]byte, error) {
	encryptedDocumentID, _, _, err := r.formatter.format(r.name, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the encrypted document ID: %w", err)
	}

	encryptedDocumentBytes, err := r.restClient.readDocument(r.vaultID, encryptedDocumentID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve document from EDV server: %w", err)
	}

	return encryptedDocumentBytes, nil
}

func (r *restStore) getEncryptedDocumentStoredUnderRandomID(key string) ([]byte, error) {
	if r.returnFullDocumentsOnQuery {
		encryptedDocumentBytes, err := r.getFullDocumentViaKeyTagQuery(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get full document via query: %w", err)
		}

		return encryptedDocumentBytes, nil
	}

	documentID, err := r.getDocumentIDViaKeyTagQuery(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get document ID via key tag query: %w", err)
	}

	encryptedDocumentBytes, err := r.restClient.readDocument(r.vaultID, documentID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve document from EDV server: %w", err)
	}

	return encryptedDocumentBytes, nil
}

func (r *restStore) deleteDocumentUsingDeterministicID(key string) error {
	edvDocumentID, err := r.formatter.generateDeterministicDocumentID(r.name, key)
	if err != nil {
		return fmt.Errorf("failed to generate the encrypted document ID: %w", err)
	}

	err = r.restClient.deleteDocument(r.vaultID, edvDocumentID)
	if err != nil && !errors.Is(err, spi.ErrDataNotFound) {
		return fmt.Errorf("unexpected failure while deleting document in EDV server: %w", err)
	}

	return nil
}

func (r *restStore) lockAndDeleteDocumentStoredUnderRandomID(key string) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.deleteDocumentStoredUnderRandomID(key)
}

func (r *restStore) getFullDocumentViaKeyTagQuery(key string) ([]byte, error) {
	formattedKeyTag, err := r.formatter.formatTag(r.name, spi.Tag{Value: key})
	if err != nil {
		return nil, fmt.Errorf("failed to format key tag: %w", err)
	}

	edvQuery := query{
		Equals:              []map[string]string{{formattedKeyTag.Name: formattedKeyTag.Value}},
		ReturnFullDocuments: true,
	}

	_, matchingDocuments, err := r.restClient.query(r.vaultID, edvQuery)
	if err != nil {
		return nil, fmt.Errorf("failure while querying vault: %w", err)
	}

	if len(matchingDocuments) == 0 {
		return nil, fmt.Errorf("no document matching the query was found: %w", spi.ErrDataNotFound)
	} else if len(matchingDocuments) > 1 {
		return nil, errors.New("multiple documents matching the query were found, " +
			"but only one was expected")
	}

	encryptedDocumentBytes, err := json.Marshal(matchingDocuments[0])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted document into bytes: %w", err)
	}

	return encryptedDocumentBytes, nil
}

func (r *restStore) query(edvQuery query) (spi.Iterator, error) {
	documentURLs, documents, err := r.restClient.query(r.vaultID, edvQuery)
	if err != nil {
		return nil, fmt.Errorf("failure while querying vault: %w", err)
	}

	if documentURLs != nil {
		documentIDs := make([]string, len(documentURLs))

		for i, documentURL := range documentURLs {
			documentIDs[i] = getDocIDFromURL(documentURL)
		}

		return &restIterator{
			vaultID: r.vaultID, restClient: r.restClient, formatter: r.formatter,
			documentIDs: documentIDs,
		}, nil
	}

	allDocumentsBytes := make([][]byte, len(documents))

	for i, document := range documents {
		documentBytes, err := json.Marshal(document)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal document into bytes: %w", err)
		}

		allDocumentsBytes[i] = documentBytes
	}

	return &restIterator{
		vaultID: r.vaultID, restClient: r.restClient, formatter: r.formatter,
		documents: allDocumentsBytes,
	}, nil
}

func (r *restStore) fastBatchUsingBatchExtension(operations []spi.Operation) error {
	var vaultOperations []vaultOperation

	var err error

	if r.formatter.UsesDeterministicKeyFormatting() {
		vaultOperations, err = r.generateVaultOperationsUsingDeterministicIDs(operations)
		if err != nil {
			return fmt.Errorf("failed to generate vault operations using deterministic IDs: %w", err)
		}
	} else {
		r.lock.Lock()
		defer r.lock.Unlock()

		vaultOperations, err = r.createVaultOperationsUsingNonDeterministicIDs(operations)
		if err != nil {
			return fmt.Errorf("failed to create vault operations using random document IDs: %w", err)
		}
	}

	err = r.restClient.batch(r.vaultID, vaultOperations)
	if err != nil {
		return fmt.Errorf("failure while executing batch operation in EDV server: %w", err)
	}

	return nil
}

func (r *restStore) slowBatchUsingStandardEndpoints(operations []spi.Operation) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, operation := range operations {
		err := r.executeOperationUsingStandardEndpoints(operation)
		if err != nil {
			return fmt.Errorf("failed to execute operation using standard endpoints: %w", err)
		}
	}

	return nil
}

func (r *restStore) executeOperationUsingStandardEndpoints(operation spi.Operation) error {
	if operation.Value == nil {
		err := r.executeDeleteOperationUsingStandardEndpoints(operation)
		if err != nil {
			return fmt.Errorf("failed to execute delete operation using standard endpoints: %w", err)
		}
	} else {
		err := r.executePutOperationUsingStandardEndpoints(operation)
		if err != nil {
			return fmt.Errorf("failed to execute put operation using standard endpoints: %w", err)
		}
	}

	return nil
}

func (r *restStore) executeDeleteOperationUsingStandardEndpoints(operation spi.Operation) error {
	if r.formatter.UsesDeterministicKeyFormatting() {
		err := r.deleteDocumentUsingDeterministicID(operation.Key)
		if err != nil {
			return fmt.Errorf("failed to delete document using deterministic ID: %w", err)
		}
	} else {
		err := r.deleteDocumentStoredUnderRandomID(operation.Key)
		if err != nil {
			return fmt.Errorf("failed to delete document using random ID: %w", err)
		}
	}

	return nil
}

func (r *restStore) executePutOperationUsingStandardEndpoints(operation spi.Operation) error {
	if r.formatter.UsesDeterministicKeyFormatting() {
		err := r.putUsingDeterministicDocumentID(operation.Key, operation.Value, operation.Tags)
		if err != nil {
			return fmt.Errorf("failed to store data using a deterministic document ID: %w", err)
		}
	} else {
		err := r.appendKeyTagAndPutUsingRandomDocumentID(operation.Key, operation.Value, operation.Tags)
		if err != nil {
			return fmt.Errorf("failed to store data using a random document ID: %w", err)
		}
	}

	return nil
}

func (r *restStore) appendKeyTagAndPutUsingRandomDocumentID(key string, value []byte, tags []spi.Tag) error {
	tags = append(tags, spi.Tag{Value: key})

	return r.putUsingRandomDocumentID(key, value, tags)
}

func (r *restStore) putUsingRandomDocumentID(key string, value []byte, tags []spi.Tag) error {
	var existingDocumentID string

	existingDocumentBytes, err := r.getEncryptedDocumentStoredUnderRandomID(key)
	if err == nil {
		var existingDocument encryptedDocument

		err = json.Unmarshal(existingDocumentBytes, &existingDocument)
		if err != nil {
			return fmt.Errorf("failed to unmarshal existing document bytes: %w", err)
		}

		existingDocumentID = existingDocument.ID
	} else if !errors.Is(err, spi.ErrDataNotFound) {
		return fmt.Errorf(`failed to determine if an EDV document for key "%s" in store "%s" already exists: %w`,
			key, r.name, err)
	}

	// With random IDs, there's no benefit to using the batch endpoint extension for a single Put,
	// so we might as well use the standard endpoints.

	if existingDocumentID == "" {
		documentID, err := generateRandomDocumentID()
		if err != nil {
			return fmt.Errorf("failed to generate a random document ID: %w", err)
		}

		err = r.formatTagsThenCreateDocument(key, documentID, value, tags)
		if err != nil {
			return fmt.Errorf("failed to format tags then create document: %w", err)
		}
	} else {
		err := r.updateDocument(key, existingDocumentID, value, tags)
		if err != nil {
			return fmt.Errorf("failed to update document: %w", err)
		}
	}

	return nil
}

func (r *restStore) formatTagsThenCreateDocument(key, documentID string, value []byte, tags []spi.Tag) error {
	formattedTags, err := r.formatter.formatTags(r.name, tags)
	if err != nil {
		return fmt.Errorf("failed to format tags: %w", err)
	}

	err = r.createDocument(key, documentID, value, tags, formattedTags)
	if err != nil {
		return fmt.Errorf("failed to create document: %w", err)
	}

	return nil
}

func (r *restStore) createDocument(key, documentID string, value []byte, tags, formattedTags []spi.Tag) error {
	encryptedDocumentBytes, err :=
		r.formatter.formatValue(key, documentID, value, tags, formattedTags)
	if err != nil {
		return fmt.Errorf("failed to generate the encrypted document: %w", err)
	}

	_, err = r.restClient.createDocument(r.vaultID, encryptedDocumentBytes)
	if err != nil {
		return fmt.Errorf("failed to create document in EDV server: %w", err)
	}

	return nil
}

func (r *restStore) deleteDocumentStoredUnderRandomID(key string) error {
	encryptedDocumentID, err := r.determineRandomDocumentIDViaVaultQuery(key)
	if err != nil {
		// It's not considered an error to attempt deleting a value that doesn't exist.
		if errors.Is(err, spi.ErrDataNotFound) {
			return nil
		}

		return fmt.Errorf("failed to determine previously generated random document ID: %w", err)
	}

	err = r.restClient.deleteDocument(r.vaultID, encryptedDocumentID)
	if err != nil {
		return fmt.Errorf("unexpected failure while deleting document in EDV server: %w", err)
	}

	return nil
}

func (r *restStore) generateVaultOperationsUsingDeterministicIDs(operations []spi.Operation) ([]vaultOperation, error) {
	vaultOperations := make([]vaultOperation, len(operations))

	for i, operation := range operations {
		var edvOperation string

		if operation.Value == nil {
			edvOperation = deleteDocumentVaultOperation
		} else {
			edvOperation = upsertDocumentVaultOperation
		}

		encryptedDocumentID, encryptedDocumentBytes, _, err :=
			r.formatter.format(r.name, operation.Key, operation.Value, operation.Tags...)
		if err != nil {
			return nil, fmt.Errorf("failed to generate the encrypted document ID and "+
				"encrypted document bytes: %w", err)
		}

		vaultOperations[i] = vaultOperation{
			Operation:         edvOperation,
			DocumentID:        encryptedDocumentID,
			EncryptedDocument: encryptedDocumentBytes,
		}
	}

	return vaultOperations, nil
}

func (r *restStore) createVaultOperationsUsingNonDeterministicIDs(
	operations []spi.Operation) ([]vaultOperation, error) {
	var vaultOperations []vaultOperation

	resolvedIDs := make(map[string]string, len(operations))

	for _, operation := range operations {
		if operation.Value == nil {
			deleteOperation, err := r.createVaultDeleteOperation(resolvedIDs, operation)
			if err != nil {
				return nil, fmt.Errorf("failed to create vault delete operation: %w", err)
			}

			// An empty ID in the returned operation means that it's not needed or is redundant with another delete operation.
			if deleteOperation.DocumentID != "" {
				vaultOperations = append(vaultOperations, deleteOperation)
			}
		} else {
			putOperation, err := r.createVaultUpsertOperation(resolvedIDs, operation)
			if err != nil {
				return nil, fmt.Errorf("failed to create vault upsert operation: %w", err)
			}

			vaultOperations = append(vaultOperations, putOperation)
		}
	}

	return vaultOperations, nil
}

func (r *restStore) createVaultDeleteOperation(resolvedIDs map[string]string,
	operation spi.Operation) (vaultOperation, error) {
	documentID, err := r.determineDocumentIDToUseForOperation(resolvedIDs, operation.Key)
	if err != nil {
		return vaultOperation{}, fmt.Errorf("unexpected failure while determining document ID to use: %w", err)
	}

	// If the ID wasn't found, or is already being deleted (is blank either way),
	// then there's nothing to delete, and so this operation is not needed.
	if documentID != "" {
		// In the event that a user does a Put, Delete, Put within the same batch, all with the same key, then we
		// should make sure that second Put uses a fresh random document ID.
		// This is in order to be consistent with what would normally happen when doing a Put after a Delete in a
		// non-batch call. The key is mapped to a blank string below, which is used to indicate that
		// a new random document ID should be generated in any subsequent Put operations for the same key within this batch.
		resolvedIDs[operation.Key] = ""

		return vaultOperation{Operation: deleteDocumentVaultOperation, DocumentID: documentID}, nil
	}

	// This empty operation will be dropped in the parent method.
	return vaultOperation{}, nil
}

func (r *restStore) createVaultUpsertOperation(resolvedIDs map[string]string,
	operation spi.Operation) (vaultOperation, error) {
	documentID, err := r.determineDocumentIDToUseForOperation(resolvedIDs, operation.Key)
	if err != nil {
		return vaultOperation{}, fmt.Errorf("unexpected failure while determining document ID to use: %w", err)
	}

	tagsToFormat := appendKeyTag(operation)

	var upsertOperation vaultOperation

	if documentID == "" {
		upsertOperation, err = r.createVaultUpsertOperationUsingNewDocumentID(resolvedIDs, operation, tagsToFormat)
		if err != nil {
			return vaultOperation{}, fmt.Errorf("failed to create vault upsert operation using a "+
				"new document ID: %w", err)
		}
	} else {
		upsertOperation, err =
			r.createVaultUpsertOperationUsingExistingDocumentID(resolvedIDs, documentID, operation, tagsToFormat)
		if err != nil {
			return vaultOperation{}, fmt.Errorf("failed to create vault upsert operation using an "+
				"existing document ID: %w", err)
		}
	}

	return upsertOperation, nil
}

func (r *restStore) createVaultUpsertOperationUsingNewDocumentID(resolvedIDs map[string]string,
	operation spi.Operation, tagsToFormat []spi.Tag) (vaultOperation, error) {
	documentID, encryptedDocumentBytes, _, err :=
		r.formatter.format(r.name, "", operation.Value, tagsToFormat...)
	if err != nil {
		return vaultOperation{}, fmt.Errorf("failed to generate the encrypted document: %w", err)
	}

	resolvedIDs[operation.Key] = documentID

	return vaultOperation{Operation: upsertDocumentVaultOperation, EncryptedDocument: encryptedDocumentBytes}, nil
}

func (r *restStore) createVaultUpsertOperationUsingExistingDocumentID(resolvedIDs map[string]string, documentID string,
	operation spi.Operation, tagsToFormat []spi.Tag) (vaultOperation, error) {
	formattedTags, err := r.formatter.formatTags(r.name, tagsToFormat)
	if err != nil {
		return vaultOperation{}, fmt.Errorf("failed to format tags: %w", err)
	}

	encryptedDocumentBytes, err :=
		r.formatter.formatValue(operation.Key, documentID, operation.Value, tagsToFormat, formattedTags)
	if err != nil {
		return vaultOperation{}, fmt.Errorf("failed to format value: %w", err)
	}

	resolvedIDs[operation.Key] = documentID

	return vaultOperation{Operation: upsertDocumentVaultOperation, EncryptedDocument: encryptedDocumentBytes}, nil
}

func (r *restStore) determineDocumentIDToUseForOperation(resolvedIDs map[string]string,
	currentOperationKey string) (string, error) {
	// There are several cases to consider:
	// 1. First, check the resolvedIDs slice. It contains the document IDs used in previous put operations within
	//	  this batch. If the key is found then we must use the associated document ID in order to ensure we don't create
	//    duplicates in the database. If a document ID is found in the map but it's set to a blank string,
	//    then we know from the createVaultDeleteOperation method that this document ID has been effectively
	//    marked for deletion and should not be reused.
	// 2. If the resolvedIDs slice doesn't have the document ID and the key wasn't previously marked for deletion,
	//    then we have to query the store. If the key is found, then that means that we must use that existing
	//    document ID for whichever operation is calling this method.
	// 3. If the document ID was marked for deletion, then we should not query the store. In the case of a Put,
	//    we want to make sure that a fresh random ID gets generated instead of reusing the
	//    old one in order to be consistent with the equivalent non-batched operations.
	//    In the case of a Delete, the query is simply unnecessary.
	documentIDToUse, isMarkedForDeletion :=
		getDocumentIDFromPreviouslyResolvedDocumentIDs(resolvedIDs, currentOperationKey)

	// If we haven't determined the document ID yet, then we must query the vault. If the document ID still
	// can't be found, then it must not exist.
	if documentIDToUse == "" && !isMarkedForDeletion {
		var err error

		documentIDToUse, err = r.determineRandomDocumentIDViaVaultQuery(currentOperationKey)
		if err != nil && !errors.Is(err, spi.ErrDataNotFound) {
			return "", fmt.Errorf("unexpected failure while attempting to "+
				"determine document ID via vault query: %w", err)
		}
	}

	return documentIDToUse, nil
}

func (r *restStore) determineRandomDocumentIDViaVaultQuery(key string) (string, error) {
	documentID, err := r.getDocumentIDViaKeyTagQuery(key)
	if err != nil {
		return "", fmt.Errorf("failed to get document ID via key tag query: %w", err)
	}

	return documentID, nil
}

func (r *restStore) getDocumentIDViaKeyTagQuery(key string) (string, error) {
	formattedKeyTag, err := r.formatter.formatTag(r.name, spi.Tag{Value: key})
	if err != nil {
		return "", fmt.Errorf("failed to format key tag: %w", err)
	}

	edvQuery := query{
		Equals:              []map[string]string{{formattedKeyTag.Name: formattedKeyTag.Value}},
		ReturnFullDocuments: false,
	}

	matchingDocumentsURLs, _, err := r.restClient.query(r.vaultID, edvQuery)
	if err != nil {
		return "", fmt.Errorf("failure while querying EDV server: %w", err)
	}

	if len(matchingDocumentsURLs) == 0 {
		return "", spi.ErrDataNotFound
	} else if len(matchingDocumentsURLs) > 1 {
		return "", errors.New("multiple documents matching the query were found, " +
			"but only one was expected")
	}

	return getDocIDFromURL(matchingDocumentsURLs[0]), nil
}

func (r *restStore) generateEDVQuery(expression string) (query, error) {
	if expression == "" {
		return query{}, errInvalidQueryExpressionFormat
	}

	orCriteria := strings.Split(expression, "||")

	edvQuery := query{
		Equals:              make([]map[string]string, len(orCriteria)),
		Has:                 "",
		ReturnFullDocuments: r.returnFullDocumentsOnQuery,
	}

	for i, orCriterion := range orCriteria {
		edvQuerySubfilter, err := r.generateEDVQuerySubfilter(orCriterion)
		if err != nil {
			return query{}, err
		}

		edvQuery.Equals[i] = edvQuerySubfilter
	}

	// See comments above the generateEDVQuerySubfilter method for an explanation of the code below.
	if len(edvQuery.Equals) == 1 && len(edvQuery.Equals[0]) == 1 {
		for formattedTagName, formattedTagValue := range edvQuery.Equals[0] {
			if formattedTagValue == "" {
				edvQuery.Equals = nil
				edvQuery.Has = formattedTagName
			}
		}
	}

	return edvQuery, nil
}

// As of writing, the EDV spec does not have an official way to do an attribute name (tag name/"has") only query when
// doing a multiple attribute query. I have an open PR in the spec to address this. In the meantime, the TrustBloc EDV
// implementation interprets a blank attribute value as behaving like an attribute name only (tag name/"has") query,
// so that's what this method does.
// In the case of the overall query being just a single attribute name only, the method that calls this will ensure that
// a "has" query is used in order to ensure maximum compatibility.
func (r *restStore) generateEDVQuerySubfilter(expression string) (map[string]string, error) {
	subfilter := make(map[string]string)

	andCriteria := strings.Split(expression, "&&")

	for _, andCriterion := range andCriteria {
		criterionSplitByTagNameAndValue := strings.Split(andCriterion, ":")

		switch len(criterionSplitByTagNameAndValue) {
		case criterionTagNameOnlyLength:
			formattedTag, err := r.formatter.formatTag(r.name, spi.Tag{Name: criterionSplitByTagNameAndValue[0]})
			if err != nil {
				return nil, fmt.Errorf("failed to format tag for querying: %w", err)
			}

			subfilter[formattedTag.Name] = ""
		case criterionTagNameAndValueLength:
			formattedTag, err := r.formatter.formatTag(r.name,
				spi.Tag{Name: criterionSplitByTagNameAndValue[0], Value: criterionSplitByTagNameAndValue[1]})
			if err != nil {
				return nil, fmt.Errorf("failed to format tag for querying: %w", err)
			}

			subfilter[formattedTag.Name] = formattedTag.Value
		default:
			return nil, errInvalidQueryExpressionFormat
		}
	}

	return subfilter, nil
}

type restIterator struct {
	vaultID      string
	restClient   *restClient
	formatter    *EncryptedFormatter
	documentIDs  []string
	documents    [][]byte
	currentIndex int
	currentKey   string
	currentValue []byte
	currentTags  []spi.Tag
}

func (r *restIterator) Next() (bool, error) {
	if len(r.documentIDs) == r.currentIndex || len(r.documentIDs) == 0 {
		if len(r.documents) == r.currentIndex || len(r.documents) == 0 {
			return false, nil
		}
	}

	var err error

	if r.documents != nil {
		r.currentKey, r.currentValue, r.currentTags, err = r.formatter.Deformat("", r.documents[r.currentIndex])
		if err != nil {
			return false, fmt.Errorf("failed to deformat encrypted document bytes: %w", err)
		}

		r.currentIndex++

		return true, nil
	}

	encryptedDocumentBytes, err := r.restClient.readDocument(r.vaultID, r.documentIDs[r.currentIndex])
	if err != nil {
		return false, fmt.Errorf("failed to retrieve document from EDV server: %w", err)
	}

	r.currentKey, r.currentValue, r.currentTags, err = r.formatter.Deformat("", encryptedDocumentBytes)
	if err != nil {
		return false, fmt.Errorf("failed to deformat encrypted document bytes: %w", err)
	}

	r.currentIndex++

	return true, nil
}

func (r *restIterator) Key() (string, error) {
	return r.currentKey, nil
}

func (r *restIterator) Value() ([]byte, error) {
	return r.currentValue, nil
}

func (r *restIterator) Tags() ([]spi.Tag, error) {
	if r.formatter.UsesDeterministicKeyFormatting() {
		return r.currentTags, nil
	}

	return filterOutKeyTag(r.currentTags, r.currentKey), nil
}

func (r *restIterator) TotalItems() (int, error) {
	if len(r.documentIDs) == 0 {
		return len(r.documents), nil
	}

	return len(r.documentIDs), nil
}

// Nothing to close for a restIterator.
func (r *restIterator) Close() error {
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

func filterOutKeyTag(tags []spi.Tag, keyToFilterOut string) []spi.Tag {
	var filteredTags []spi.Tag

	for _, tag := range tags {
		if !(tag.Name == "" && tag.Value == keyToFilterOut) {
			filteredTags = append(filteredTags, tag)
		}
	}

	return filteredTags
}

func getQueryOptions(options []spi.QueryOption) spi.QueryOptions {
	var queryOptions spi.QueryOptions

	for _, option := range options {
		option(&queryOptions)
	}

	return queryOptions
}

func checkForUnsupportedQueryOptions(options []spi.QueryOption) error {
	querySettings := getQueryOptions(options)

	if querySettings.InitialPageNum != 0 {
		return errors.New("EDV does not support setting the initial page number of query results")
	}

	if querySettings.SortOptions != nil {
		return errors.New("EDV does not support custom sort options for query results")
	}

	return nil
}

func getDocIDFromURL(docURL string) string {
	splitBySlashes := strings.Split(docURL, `/`)
	docIDToRetrieve := splitBySlashes[len(splitBySlashes)-1]

	return docIDToRetrieve
}

func getDocumentIDFromPreviouslyResolvedDocumentIDs(resolvedIDs map[string]string,
	key string) (documentIDToUse string, isMarkedForDeletion bool) {
	for unformattedKey, documentID := range resolvedIDs {
		if unformattedKey == key {
			documentIDToUse = documentID

			if documentID == "" {
				isMarkedForDeletion = true
			}

			break
		}
	}

	return documentIDToUse, isMarkedForDeletion
}

// Returns a new slice in order to avoid modifying the user's input passed in to the Batch method.
func appendKeyTag(operation spi.Operation) []spi.Tag {
	tags := make([]spi.Tag, len(operation.Tags)+1)

	for j, tag := range operation.Tags {
		tags[j] = tag
	}

	tags[len(tags)-1] = spi.Tag{Value: operation.Key}

	return tags
}
