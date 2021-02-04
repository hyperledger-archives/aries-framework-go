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

	"github.com/hyperledger/aries-framework-go/component/newstorage"
)

const (
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2
)

var (
	errEmptyKey                     = errors.New("key cannot be empty")
	errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
		"it must be in the following format: TagName:TagValue")
)

// Option allows for configuration of a RESTProvider.
type Option func(opts *RESTProvider)

// WithTLSConfig is an option that allows for the definition of a secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *RESTProvider) {
		opts.restClient.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}

// WithHeaders option is for setting additional http request headers (since it's a function, it can call a remote
// authorization server to fetch the necessary info needed in these headers).
func WithHeaders(addHeadersFunc addHeaders) Option {
	return func(opts *RESTProvider) {
		opts.restClient.headersFunc = addHeadersFunc
	}
}

// WithFullDocumentsReturnedFromQueries option is a performance optimization that speeds up queries by getting
// full documents from the EDV server instead of only document locations - each of which would require a separate REST
// call to retrieve. The EDV server that this RESTProvider connects to must support the TrustBloc EDV server extension
// as defined here: https://github.com/trustbloc/edv/blob/main/docs/extensions.md#return-full-documents-on-query.
func WithFullDocumentsReturnedFromQueries() Option {
	return func(restProvider *RESTProvider) {
		restProvider.returnFullDocumentsOnQuery = true
	}
}

// WithBatchEndpointExtension option is a performance optimization that allows for restStore.Batch to only require one
// REST call. The EDV server that this RESTProvider connects to must support the TrustBloc EDV server extension
// as defined here: https://github.com/trustbloc/edv/blob/main/docs/extensions.md#batch-endpoint.
func WithBatchEndpointExtension() Option {
	return func(opts *RESTProvider) {
		opts.batchEndpointExtensionEnabled = true
	}
}

// RESTProvider is a newstorage.Provider that can be used to store data in a server supporting the
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
func NewRESTProvider(edvServerURL, vaultID string, formatter *EncryptedFormatter, options ...Option) *RESTProvider {
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
func (r *RESTProvider) OpenStore(name string) (newstorage.Store, error) {
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
			namespace:                     storeName,
			formatter:                     r.formatter,
			restClient:                    r.restClient,
			returnFullDocumentsOnQuery:    r.returnFullDocumentsOnQuery,
			batchEndpointExtensionEnabled: r.batchEndpointExtensionEnabled,
			close:                         r.removeStore,
		}
		r.openStores[storeName] = newStore

		return newStore, nil
	}

	return &restStore{
		vaultID:                    r.vaultID,
		namespace:                  name,
		formatter:                  r.formatter,
		restClient:                 r.restClient,
		returnFullDocumentsOnQuery: r.returnFullDocumentsOnQuery,
	}, nil
}

// SetStoreConfig isn't needed for EDV storage, since indexes are managed by the server automatically based on the
// tags used in values. This method simply stores the configuration in memory so that it can be retrieved later
// via the GetStoreConfig method, which allows it to be more consistent with how other store implementations work.
// TODO (#2492) Store store config in persistent EDV storage for true consistency with other store implementations.
func (r *RESTProvider) SetStoreConfig(name string, config newstorage.StoreConfiguration) error {
	openStore, ok := r.openStores[name]
	if !ok {
		return newstorage.ErrStoreNotFound
	}

	openStore.config = config

	return nil
}

// GetStoreConfig returns the store configuration currently stored in memory.
func (r *RESTProvider) GetStoreConfig(name string) (newstorage.StoreConfiguration, error) {
	openStore, ok := r.openStores[name]
	if !ok {
		return newstorage.StoreConfiguration{}, newstorage.ErrStoreNotFound
	}

	return openStore.config, nil
}

// GetOpenStores returns all currently open stores.
func (r *RESTProvider) GetOpenStores() []newstorage.Store {
	r.lock.RLock()
	defer r.lock.RUnlock()

	openStores := make([]newstorage.Store, len(r.openStores))

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
	namespace                     string
	formatter                     *EncryptedFormatter
	restClient                    *restClient
	config                        newstorage.StoreConfiguration
	returnFullDocumentsOnQuery    bool
	batchEndpointExtensionEnabled bool
	close                         closer
}

// Put stores data into an EDV server.
func (r *restStore) Put(key string, value []byte, tags ...newstorage.Tag) error {
	if key == "" {
		return errEmptyKey
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	// If the batch endpoint extension is enabled, we can avoid the need to read the document first since the batch
	// endpoint does upserts instead of explicit create and updates.
	if r.batchEndpointExtensionEnabled {
		encryptedDocumentID, encryptedDocumentBytes, _, err :=
			r.formatter.format(r.namespace, key, value, tags...)
		if err != nil {
			return fmt.Errorf("failed to generate the encrypted document ID and "+
				"encrypted document bytes: %w", err)
		}

		_, err = r.restClient.Batch(r.vaultID, batch{vaultOperation{
			Operation:         upsertDocumentVaultOperation,
			DocumentID:        encryptedDocumentID,
			EncryptedDocument: encryptedDocumentBytes,
		}})
		if err != nil {
			return fmt.Errorf("failed to put data in EDV server via the batch endpoint "+
				"(is it enabled in the EDV server?): %w", err)
		}
	}

	var needsUpdate bool

	// TODO (#2493): Encrypted document ID gets generated twice in the flow below - once by the Get call
	//  and once in r.saveDataToEDVServer. It should be possible to refactor the code to avoid this.

	_, err := r.get(key)
	if err == nil {
		needsUpdate = true
	} else if !errors.Is(err, newstorage.ErrDataNotFound) {
		return fmt.Errorf(`failed to determine if an EDV document for key "%s" in store "%s" already exists: %w`,
			key, r.namespace, err)
	}

	err = r.saveDataToEDVServer(key, value, tags, needsUpdate)
	if err != nil {
		return fmt.Errorf("failed to store data in EDV server: %w", err)
	}

	return nil
}

func (r *restStore) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	encryptedDocumentBytes, err := r.get(key)
	if err != nil {
		return nil, err
	}

	_, value, _, err := r.formatter.Deformat("", encryptedDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt encrypted document: %w", err)
	}

	return value, nil
}

func (r *restStore) GetTags(key string) ([]newstorage.Tag, error) {
	encryptedDocumentID, _, _, err := r.formatter.format(r.namespace, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the encrypted document ID: %w", err)
	}

	encryptedDocumentBytes, err := r.restClient.readDocument(r.vaultID, encryptedDocumentID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve document from EDV server: %w", err)
	}

	_, _, tags, err := r.formatter.Deformat("", encryptedDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt encrypted document: %w", err)
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

	for _, key := range keys {
		if key == "" {
			return nil, errors.New("no keys are allowed to be empty")
		}
	}

	values := make([][]byte, len(keys))

	for i, key := range keys {
		var err error

		values[i], err = r.Get(key)
		if err != nil && !errors.Is(err, newstorage.ErrDataNotFound) {
			return nil, fmt.Errorf(`unexpected failure while getting value for key "%s": %w`, key, err)
		}
	}

	return values, nil
}

// EDV doesn't support paging, so it has no use for the paging query option (which is the only one currently).
func (r *restStore) Query(expression string, _ ...newstorage.QueryOption) (newstorage.Iterator, error) {
	expressionTagName, expressionTagValue, err := parseQueryExpression(expression)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query expression: %w", err)
	}

	_, _, tags, err := r.formatter.format(r.namespace, "", nil,
		newstorage.Tag{Name: expressionTagName, Value: expressionTagValue})
	if err != nil {
		return nil, fmt.Errorf("failed to format tag for querying: %w", err)
	}

	return r.query(tags[0])
}

func (r *restStore) Delete(key string) error {
	if key == "" {
		return errEmptyKey
	}

	edvDocumentID, _, _, err := r.formatter.format(r.namespace, key, nil)
	if err != nil {
		return fmt.Errorf("failed to generate the encrypted document ID: %w", err)
	}

	err = r.restClient.DeleteDocument(r.vaultID, edvDocumentID)
	if err != nil && !errors.Is(err, newstorage.ErrDataNotFound) {
		return fmt.Errorf("unexpected failure while deleting document in EDV server: %w", err)
	}

	return nil
}

// TODO (#2494): Return a newstorage.MultiError from here in the case of a failure.
func (r *restStore) Batch(operations []newstorage.Operation) error {
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
	r.close(r.namespace)

	return nil
}

// restStore doesn't queue values, so there's never anything to flush.
func (r *restStore) Flush() error {
	return nil
}

func (r *restStore) saveDataToEDVServer(key string, value []byte, tags []newstorage.Tag, needsUpdate bool) error {
	encryptedDocumentID, encryptedDocumentBytes, _, err :=
		r.formatter.format(r.namespace, key, value, tags...)
	if err != nil {
		return fmt.Errorf("failed to generate the encrypted document: %w", err)
	}

	if needsUpdate {
		err = r.restClient.updateDocument(r.vaultID, encryptedDocumentID, encryptedDocumentBytes)
		if err != nil {
			return fmt.Errorf("failed to update existing document in EDV server: %w", err)
		}
	} else {
		_, err = r.restClient.createDocument(r.vaultID, encryptedDocumentBytes)
		if err != nil {
			return fmt.Errorf("failed to create document in EDV server: %w", err)
		}
	}

	return nil
}

func (r *restStore) get(key string) ([]byte, error) {
	encryptedDocumentID, _, _, err := r.formatter.format(r.namespace, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the encrypted document ID: %w", err)
	}

	encryptedDocumentBytes, err := r.restClient.readDocument(r.vaultID, encryptedDocumentID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve document from EDV server: %w", err)
	}

	return encryptedDocumentBytes, nil
}

func (r *restStore) fastBatchUsingBatchExtension(operations []newstorage.Operation) error {
	edvBatch := make(batch, len(operations))

	for i, operation := range operations {
		var edvOperation string

		if operation.Value == nil {
			edvOperation = deleteDocumentVaultOperation
		} else {
			edvOperation = upsertDocumentVaultOperation
		}

		encryptedDocumentID, encryptedDocumentBytes, _, err :=
			r.formatter.format(r.namespace, operation.Key, operation.Value, operation.Tags...)
		if err != nil {
			return fmt.Errorf("failed to generate the encrypted document ID and encrypted document bytes: %w",
				err)
		}

		edvBatch[i] = vaultOperation{
			Operation:         edvOperation,
			DocumentID:        encryptedDocumentID,
			EncryptedDocument: encryptedDocumentBytes,
		}
	}

	_, err := r.restClient.Batch(r.vaultID, edvBatch)
	if err != nil {
		return fmt.Errorf("failure while executing batch operation in EDV server: %w", err)
	}

	return nil
}

func (r *restStore) slowBatchUsingStandardEndpoints(operations []newstorage.Operation) error {
	for _, operation := range operations {
		if operation.Value == nil {
			err := r.Delete(operation.Key)
			if err != nil {
				return fmt.Errorf("failed to delete: %w", err)
			}
		} else {
			err := r.Put(operation.Key, operation.Value, operation.Tags...)
			if err != nil {
				return fmt.Errorf("failed to put: %w", err)
			}
		}
	}

	return nil
}

func (r *restStore) query(tag newstorage.Tag) (newstorage.Iterator, error) {
	if r.returnFullDocumentsOnQuery {
		documents, err := r.restClient.queryVaultForFullDocuments(r.vaultID, tag.Name, tag.Value)
		if err != nil {
			return nil, fmt.Errorf("failure while querying vault: %w", err)
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

	documentURLs, err := r.restClient.queryVault(r.vaultID, tag.Name, tag.Value)
	if err != nil {
		return nil, fmt.Errorf("failure while querying EDV server: %w", err)
	}

	documentIDs := make([]string, len(documentURLs))

	for i, documentURL := range documentURLs {
		documentIDs[i] = getDocIDFromURL(documentURL)
	}

	return &restIterator{
		vaultID: r.vaultID, restClient: r.restClient, formatter: r.formatter,
		documentIDs: documentIDs,
	}, nil
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
	currentTags  []newstorage.Tag
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

func (r *restIterator) Tags() ([]newstorage.Tag, error) {
	return r.currentTags, nil
}

// Nothing to close for a restIterator.
func (r *restIterator) Close() error {
	return nil
}

func parseQueryExpression(expression string) (string, string, error) {
	if expression == "" {
		return "", "", errInvalidQueryExpressionFormat
	}

	expressionSplit := strings.Split(expression, ":")

	var expressionTagName, expressionTagValue string

	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		expressionTagName = expressionSplit[0]
	case expressionTagNameAndValueLength:
		expressionTagName = expressionSplit[0]
		expressionTagValue = expressionSplit[1]
	default:
		return "", "", errInvalidQueryExpressionFormat
	}

	return expressionTagName, expressionTagValue, nil
}

func getDocIDFromURL(docURL string) string {
	splitBySlashes := strings.Split(docURL, `/`)
	docIDToRetrieve := splitBySlashes[len(splitBySlashes)-1]

	return docIDToRetrieve
}
