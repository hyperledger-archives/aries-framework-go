/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/models"
)

const (
	storeIndexName             = "StoreName"
	contentTypeApplicationJSON = "application/json"
	locationHeaderName         = "Location"

	failStoreEDVDocument                       = "failed to store EDV document: %w"
	failComputeMACStoreIndexName               = "failed to compute MAC for the store index name: %w"
	failComputeMACStoreIndexValue              = "failed to compute MAC for the store index value: %w"
	failCreateIndexedAttributes                = "failed to create indexed attributes: %w"
	failComputeBase64EncodedStoreIndexValueMAC = "failed to compute Base64-encoded store index value MAC: %w"
	failAddEncryptedIndices                    = "failed to add encrypted indices to encrypted document: %w"
	failCreateDocumentInEDVServer              = "failed to create document in EDV server: %w"
	failUpdateDocumentInEDVServer              = "failed to update existing document in EDV server: %w"
	failGenerateEDVDocumentID                  = "failed to generate the EDV document ID for key %s: %w"
	failQueryVaultForFullDocumentsInEDVServer  = "failed to query vault for full documents in EDV server: %w"
	failQueryVaultInEDVServer                  = "failed to query vault in EDV server: %w"
	failRetrieveDocumentFromEDVServer          = "failed to retrieve document from EDV server: %w"
	failDeleteDocumentInEDVServer              = "failed to delete document in EDV server: %w"
	failGetAllFullDocumentsViaQuery            = "failed to get all full documents via query: %w"
	failGetAllDocumentLocations                = "failed to get all document locations: %w"
	failGetAllDocuments                        = "failed to get all documents: %w"
	failBatchInEDVServer                       = "failed to do batch operations in EDV server: %w"
	failComputeMACBasedOnKey                   = "failed to compute MAC based on key %s: %w"

	failSendGETRequest                 = "failed to send GET request: %w"
	failSendPOSTRequest                = "failed to send POST request: %w"
	failCreateRequest                  = "failed to create request: %w"
	failSendRequest                    = "failed to send request: %w"
	failReadResponseBody               = "failed to read response body: %w"
	failMarshalQuery                   = "failed to marshal query: %w"
	failMarshalBatch                   = "failed to marshal batch: %w"
	failUnmarshalEncryptedDocuments    = "failed to unmarshal encrypted documents: %w"
	failUnmarshalBatchResponses        = "failed to unmarshal batch responses: %w"
	failResponseFromEDVServer          = "status code %d was returned along with the following message: %s"
	failResponseFromEDVServerWithError = "error: %w, status code %d was returned along with the following message: %s"
	failUnmarshalDocumentLocations     = "failed to unmarshal response bytes into document locations: %w"

	createDocumentRequestLogMsg = "Sending request to create the following document: %s"
	updateDocumentRequestLogMsg = "Sending request to update the following document: %s"
	sendRequestLogMsg           = `Sent %s request to %s. Response status code: %d Response body: %s`
	failCloseResponseBodyLogMsg = "Failed to close response body: %s"
)

var logger = log.New("EDV-REST-Provider")

// MACDigester represents a type that can compute MACs.
type MACDigester interface {
	ComputeMAC(data []byte, kh interface{}) ([]byte, error)
}

// MACCrypto is used for computing MACs.
type MACCrypto struct {
	kh          interface{}
	macDigester MACDigester
}

// ComputeMAC computes a MAC for data using a matching MAC primitive in kh.
func (m *MACCrypto) ComputeMAC(data string) (string, error) {
	dataMAC, err := m.macDigester.ComputeMAC([]byte(data), m.kh)
	return string(dataMAC), err
}

// NewMACCrypto returns a new instance of a MACCrypto.
func NewMACCrypto(kh interface{}, macDigester MACDigester) *MACCrypto {
	return &MACCrypto{
		kh:          kh,
		macDigester: macDigester,
	}
}

// Option configures the EDV REST provider.
type Option func(opts *RESTProvider)

// addHeaders function supports adding custom HTTP headers.
type addHeaders func(req *http.Request) (*http.Header, error)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
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

// WithFullDocumentsReturnedFromQueries option is a performance optimization that can be used only if
// the EDV server that this RESTProvider connects to supports returning full documents in query results instead of
// only the document locations.
func WithFullDocumentsReturnedFromQueries() Option {
	return func(opts *RESTProvider) {
		opts.returnFullDocumentsOnQuery = true
	}
}

// RESTProvider is a store provider that can be used to store data in a server supporting the
// data vault HTTPS API as defined in https://identity.foundation/secure-data-store/#data-vault-https-api.
type RESTProvider struct {
	vaultID                        string
	macCrypto                      *MACCrypto
	storeIndexNameMACBase64Encoded string
	restClient                     *restClient

	// Requires an EDV server that supports this capability, which is not currently in the spec,
	// but has been requested: https://github.com/decentralized-identity/confidential-storage/issues/137.
	// If enabled, allows for the Put method to execute faster by reducing the number of REST calls from 2 down to 1.
	returnFullDocumentsOnQuery bool
}

// NewRESTProvider returns a new RESTProvider. edvServerURL is the base URL for the data vault HTTPS API.
// vaultID is the ID of the vault where this provider will store data. The vault must be created in advance, and since
// the EDV REST API does not provide a method to check if a vault with a given ID exists, any errors due to a
// non-existent vault will be deferred until calls are actually made to it in the RESTStore.
// macCrypto is used to create an encrypted indices, which allow for documents to be queries based on a key
// without leaking that key to the EDV server.
func NewRESTProvider(edvServerURL, vaultID string,
	macCrypto *MACCrypto, options ...Option) (*RESTProvider, error) {
	storeIndexNameMAC, err := macCrypto.ComputeMAC(storeIndexName)
	if err != nil {
		return nil, fmt.Errorf(failComputeMACStoreIndexName, err)
	}

	client := restClient{
		edvServerURL: edvServerURL,
		httpClient:   &http.Client{},
	}

	restProvider := RESTProvider{
		vaultID:                        vaultID,
		macCrypto:                      macCrypto,
		storeIndexNameMACBase64Encoded: base64.URLEncoding.EncodeToString([]byte(storeIndexNameMAC)),
		restClient:                     &client,
	}

	for _, opt := range options {
		opt(&restProvider)
	}

	return &restProvider, nil
}

// OpenStore opens a new RESTStore, using name as the namespace.
func (r *RESTProvider) OpenStore(name string) (storage.Store, error) {
	return &RESTStore{
		vaultID:                        r.vaultID,
		name:                           name,
		macCrypto:                      r.macCrypto,
		storeIndexNameMACBase64Encoded: r.storeIndexNameMACBase64Encoded,
		restClient:                     r.restClient,
		returnFullDocumentsOnQuery:     r.returnFullDocumentsOnQuery,
	}, nil
}

// CloseStore always returns success, since EDV REST stores have no concept of "closing".
func (r *RESTProvider) CloseStore(string) error {
	return nil
}

// Close always returns success, since EDV REST stores have no concept of "closing".
func (r *RESTProvider) Close() error {
	return nil
}

// Batch performs a batch of operations within the RESTProvider.
// The EDV server must support the "Batch" extension.
// TODO (#2315) Refactor storage interface to properly accommodate this method
//  (For FormatProvider to use this, it must do a cast)
func (r *RESTProvider) Batch(batch *models.Batch) error {
	_, err := r.restClient.Batch(r.vaultID, batch)
	if err != nil {
		return fmt.Errorf(failBatchInEDVServer, err)
	}

	return nil
}

// RESTStore is a store for storing EDV documents via the REST API.
// TODO (#2315) RESTStore shouldn't be exported - it was exported to allow for batch operations. When refactoring
// the storage interface, fix this.
// TODO - BUG (#2490) RESTStores don't namespace correctly with an EDV server.
type RESTStore struct {
	vaultID                        string
	name                           string
	restClient                     *restClient
	macCrypto                      *MACCrypto
	storeIndexNameMACBase64Encoded string
	returnFullDocumentsOnQuery     bool
}

// Put stores the marshalled EncryptedDocument v into the EDV server. An encrypted index will be added to v so that we
// are able to identify which documents in the vault belong to the store r.name.
func (r *RESTStore) Put(k string, v []byte) error {
	var needsUpdate bool

	_, err := r.Get(k)
	if err == nil {
		needsUpdate = true
	} else if !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("failed to determine if an EDV document for key %s already exists: %w", k, err)
	}

	err = r.saveEDVDocumentToServer(v, needsUpdate)
	if err != nil {
		return fmt.Errorf(failStoreEDVDocument, err)
	}

	return nil
}

// Get retrieves the encrypted document from the EDV server saved under key k.
func (r *RESTStore) Get(k string) ([]byte, error) {
	edvDocumentID, err := r.generateEDVDocumentID(k)
	if err != nil {
		return nil, fmt.Errorf(failGenerateEDVDocumentID, k, err)
	}

	encryptedDocumentBytes, err := r.restClient.readDocument(r.vaultID, edvDocumentID)
	if err != nil {
		return nil, fmt.Errorf(failRetrieveDocumentFromEDVServer, err)
	}

	return encryptedDocumentBytes, nil
}

// Iterator returns all documents within the store. It does not support start and end key filtering.
func (r *RESTStore) Iterator(_, _ string) storage.StoreIterator {
	if r.returnFullDocumentsOnQuery {
		// Take a shortcut and get all the full documents from the query in one REST call.
		allDocuments, err := r.getAllFullDocumentsViaQuery()
		if err != nil {
			return &restStoreIterator{err: fmt.Errorf(failGetAllFullDocumentsViaQuery, err)}
		}

		return &restStoreIterator{documents: allDocuments}
	}
	// Get document IDs from query, then get the full document in successive calls.
	allDocumentLocations, err := r.getAllDocumentLocations()
	if err != nil {
		return &restStoreIterator{err: fmt.Errorf(failGetAllDocumentLocations, err)}
	}

	allDocuments, err := r.getAllDocuments(allDocumentLocations)
	if err != nil {
		return &restStoreIterator{err: fmt.Errorf(failGetAllDocuments, err)}
	}

	return &restStoreIterator{documents: allDocuments}
}

// Delete deletes the encrypted document in the EDV server that is tagged with the key k.
func (r *RESTStore) Delete(k string) error {
	edvDocumentID, err := r.generateEDVDocumentID(k)
	if err != nil {
		return fmt.Errorf(failGenerateEDVDocumentID, k, err)
	}

	err = r.restClient.DeleteDocument(r.vaultID, edvDocumentID)
	if err != nil {
		return fmt.Errorf(failDeleteDocumentInEDVServer, err)
	}

	return nil
}

// GenerateEDVCompatibleID generates the EDV document ID based on k and the MAC crypto key.
// TODO (#2376) Revisit how we're generating EDV document IDs, since it's technically not 100% in line with the spec.
//  (Spec requires randomly generated IDs)
func (r *RESTStore) generateEDVDocumentID(k string) (string, error) {
	hashKey, err := r.macCrypto.ComputeMAC(k)
	if err != nil {
		return "", fmt.Errorf(failComputeMACBasedOnKey, k, err)
	}

	return base58.Encode([]byte(hashKey[0:16])), nil
}

func (r *RESTStore) saveEDVDocumentToServer(v []byte, needsUpdate bool) error {
	encryptedDocument, err := r.AddEncryptedIndexTagForStoreName(v)
	if err != nil {
		return fmt.Errorf(failAddEncryptedIndices, err)
	}

	if needsUpdate {
		err = r.restClient.updateDocument(r.vaultID, encryptedDocument.ID, encryptedDocument)
		if err != nil {
			return fmt.Errorf(failUpdateDocumentInEDVServer, err)
		}
	} else {
		_, err = r.restClient.createDocument(r.vaultID, encryptedDocument)
		if err != nil {
			return fmt.Errorf(failCreateDocumentInEDVServer, err)
		}
	}

	return nil
}

func (r *RESTStore) createIndexedAttribute() ([]models.IndexedAttributeCollection, error) {
	storeIndexValueMAC, err := r.macCrypto.ComputeMAC(r.name)
	if err != nil {
		return nil, fmt.Errorf(failComputeMACStoreIndexValue, err)
	}

	storeIndexedAttribute := models.IndexedAttribute{
		Name:   r.storeIndexNameMACBase64Encoded,
		Value:  base64.URLEncoding.EncodeToString([]byte(storeIndexValueMAC)),
		Unique: false,
	}

	indexedAttributeCollection := models.IndexedAttributeCollection{
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{storeIndexedAttribute},
	}

	indexedAttributeCollections := []models.IndexedAttributeCollection{indexedAttributeCollection}

	return indexedAttributeCollections, nil
}

// AddEncryptedIndexTagForStoreName takes encryptedDocumentBytes and adds an encrypted index tag so that we can
// later identify the document as belonging to the store r.name.
// TODO (#2315) AddEncryptedIndices shouldn't be exported - it was exported to allow for batch operations.
// When refactoring the storage interface, fix this.
func (r *RESTStore) AddEncryptedIndexTagForStoreName(encryptedDocumentBytes []byte) (*models.EncryptedDocument, error) {
	var encryptedDocument models.EncryptedDocument

	err := json.Unmarshal(encryptedDocumentBytes, &encryptedDocument)
	if err != nil {
		return nil, fmt.Errorf(failUnmarshalValueIntoEncryptedDocument, err)
	}

	indexedAttributeCollection, err := r.createIndexedAttribute()
	if err != nil {
		return nil, fmt.Errorf(failCreateIndexedAttributes, err)
	}

	encryptedDocument.IndexedAttributeCollections = indexedAttributeCollection

	return &encryptedDocument, nil
}

func (r *RESTStore) getAllFullDocumentsViaQuery() ([][]byte, error) {
	storeNameIndexValueMACBase64Encoded, err := r.computeStoreIndexValueMACBase64Encoded()
	if err != nil {
		return nil, fmt.Errorf(failComputeBase64EncodedStoreIndexValueMAC, err)
	}

	allDocuments, err := r.restClient.queryVaultForFullDocuments(r.vaultID,
		r.storeIndexNameMACBase64Encoded, storeNameIndexValueMACBase64Encoded)
	if err != nil {
		return nil, fmt.Errorf(failQueryVaultForFullDocumentsInEDVServer, err)
	}

	allDocumentsBytes := make([][]byte, len(allDocuments))

	for i, document := range allDocuments {
		documentBytes, err := json.Marshal(document)
		if err != nil {
			return nil, fmt.Errorf(failMarshalEncryptedDocument, err)
		}

		allDocumentsBytes[i] = documentBytes
	}

	return allDocumentsBytes, nil
}

func (r *RESTStore) getAllDocumentLocations() ([]string, error) {
	storeNameIndexValueMACBase64Encoded, err := r.computeStoreIndexValueMACBase64Encoded()
	if err != nil {
		return nil, fmt.Errorf(failComputeBase64EncodedStoreIndexValueMAC, err)
	}

	allDocumentLocations, err := r.restClient.queryVault(r.vaultID,
		r.storeIndexNameMACBase64Encoded, storeNameIndexValueMACBase64Encoded)
	if err != nil {
		return nil, fmt.Errorf(failQueryVaultInEDVServer, err)
	}

	return allDocumentLocations, nil
}

func (r *RESTStore) getAllDocuments(allDocumentLocations []string) ([][]byte, error) {
	allDocuments := make([][]byte, len(allDocumentLocations))

	for index, documentLocation := range allDocumentLocations {
		documentID := getDocIDFromURL(documentLocation)

		encryptedDocumentBytes, err := r.restClient.readDocument(r.vaultID, documentID)
		if err != nil {
			return nil, fmt.Errorf(failRetrieveDocumentFromEDVServer, err)
		}

		allDocuments[index] = encryptedDocumentBytes
	}

	return allDocuments, nil
}

func (r *RESTStore) computeStoreIndexValueMACBase64Encoded() (string, error) {
	indexValueMAC, err := r.macCrypto.ComputeMAC(r.name)
	if err != nil {
		return "", fmt.Errorf(failComputeMACStoreIndexValue, err)
	}

	return base64.URLEncoding.EncodeToString([]byte(indexValueMAC)), nil
}

type restStoreIterator struct {
	documents       [][]byte
	currentDocument []byte
	currentIndex    int
	err             error
}

func (r *restStoreIterator) Next() bool {
	if r.isExhausted() {
		return false
	}

	r.currentDocument = r.documents[r.currentIndex]
	r.currentIndex++

	return true
}

func (r *restStoreIterator) Release() {
	r.currentIndex = 0
	r.documents = make([][]byte, 0)
	r.currentDocument = make([]byte, 0)

	r.err = errors.New("iterator released")
}

func (r *restStoreIterator) Error() error {
	return r.err
}

func (r *restStoreIterator) Key() []byte {
	if len(r.documents) == 0 || len(r.currentDocument) == 0 {
		return nil
	}

	var encryptedDocument models.EncryptedDocument

	err := json.Unmarshal(r.currentDocument, &encryptedDocument)
	if err != nil {
		r.err = fmt.Errorf("failed to unmarshal current document in iterator "+
			"into an encrypted document: %w", err)
	}

	return []byte(encryptedDocument.ID)
}

func (r *restStoreIterator) Value() []byte {
	if len(r.documents) == 0 || len(r.currentDocument) < 1 {
		return nil
	}

	return r.currentDocument
}

func (r *restStoreIterator) isExhausted() bool {
	return len(r.documents) == 0 || len(r.documents) == r.currentIndex
}

// restClient is used to make HTTP REST calls to a server supporting the
// data vault HTTPS API as defined in https://identity.foundation/secure-data-store/#data-vault-https-api
type restClient struct {
	edvServerURL string
	httpClient   *http.Client
	headersFunc  addHeaders
}

// createDocument sends the EDV server a request to store the specified document.
// The location of the newly created document is returned.
func (c *restClient) createDocument(vaultID string, document *models.EncryptedDocument) (string, error) {
	jsonToSend, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf(failMarshalEncryptedDocument, err)
	}

	logger.Debugf(createDocumentRequestLogMsg, jsonToSend)

	endpoint := fmt.Sprintf("%s/%s/documents", c.edvServerURL, vaultID)

	statusCode, hdr, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.headersFunc)
	if err != nil {
		return "", fmt.Errorf(failSendPOSTRequest, err)
	}

	if statusCode == http.StatusCreated {
		return hdr.Get(locationHeaderName), nil
	}

	return "", fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

// updateDocument sends the EDV server a request to update the specified document.
func (c *restClient) updateDocument(vaultID, docID string, document *models.EncryptedDocument) error {
	jsonToSend, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf(failMarshalEncryptedDocument, err)
	}

	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	logger.Debugf(updateDocumentRequestLogMsg, jsonToSend)

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.headersFunc)
	if err != nil {
		return fmt.Errorf(failSendPOSTRequest, err)
	}

	// TODO (#2331): StatusNoContent added for now since Transmute's EDV implementation uses it
	if statusCode == http.StatusOK || statusCode == http.StatusNoContent {
		return nil
	}

	return fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

// readDocument sends the EDV server a request to retrieve the specified document.
// The requested document, if found, is returned.
func (c *restClient) readDocument(vaultID, docID string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodGet, endpoint, nil, c.headersFunc)
	if err != nil {
		return nil, fmt.Errorf(failSendGETRequest, err)
	}

	switch statusCode {
	case http.StatusOK:
		return respBytes, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf(failResponseFromEDVServerWithError, storage.ErrDataNotFound, statusCode, respBytes)
	default:
		return nil, fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
	}
}

// queryVault queries the given vault and returns the URLs of all documents that match the given query.
func (c *restClient) queryVault(vaultID, name, value string) ([]string, error) {
	query := models.Query{
		ReturnFullDocuments: false,
		Name:                name,
		Value:               value,
	}

	jsonToSend, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf(failMarshalQuery, err)
	}

	endpoint := fmt.Sprintf("%s/%s/query", c.edvServerURL, url.PathEscape(vaultID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.headersFunc)
	if err != nil {
		return nil, fmt.Errorf(failSendPOSTRequest, err)
	}

	if statusCode == http.StatusOK {
		var docLocations []string

		err = json.Unmarshal(respBytes, &docLocations)
		if err != nil {
			return nil, fmt.Errorf(failUnmarshalDocumentLocations, err)
		}

		return docLocations, nil
	}

	return nil, fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

// queryVaultForFullDocuments queries the given vault and returns all documents that match the given query.
// Requires the EDV server to support this functionality, which is currently non-standard.
func (c *restClient) queryVaultForFullDocuments(vaultID, name, value string) ([]models.EncryptedDocument, error) {
	query := models.Query{
		ReturnFullDocuments: true,
		Name:                name,
		Value:               value,
	}

	jsonToSend, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf(failMarshalQuery, err)
	}

	endpoint := fmt.Sprintf("%s/%s/query", c.edvServerURL, url.PathEscape(vaultID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.headersFunc)
	if err != nil {
		return nil, fmt.Errorf(failSendPOSTRequest, err)
	}

	if statusCode == http.StatusOK {
		var documents []models.EncryptedDocument

		err = json.Unmarshal(respBytes, &documents)
		if err != nil {
			return nil, fmt.Errorf(failUnmarshalEncryptedDocuments, err)
		}

		return documents, nil
	}

	return nil, fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

// Batch performs batch operations within a vault.
// Requires the EDV server to support this functionality, which is currently non-standard.
func (c *restClient) Batch(vaultID string, batch *models.Batch) ([]string, error) {
	jsonToSend, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf(failMarshalBatch, err)
	}

	endpoint := fmt.Sprintf("%s/%s/batch", c.edvServerURL, url.PathEscape(vaultID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.headersFunc)
	if err != nil {
		return nil, fmt.Errorf(failSendPOSTRequest, err)
	}

	if statusCode == http.StatusOK {
		var responses []string

		err = json.Unmarshal(respBytes, &responses)
		if err != nil {
			return nil, fmt.Errorf(failUnmarshalBatchResponses, err)
		}

		return responses, nil
	}

	return nil, fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

// DeleteDocument sends the EDV server a request to delete the specified document.
func (c *restClient) DeleteDocument(vaultID, docID string) error {
	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodDelete, endpoint, nil, c.headersFunc)
	if err != nil {
		return err
	}

	if statusCode == http.StatusOK {
		return nil
	}

	return fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

func (c *restClient) sendHTTPRequest(method, endpoint string, body []byte,
	addHeadersFunc addHeaders) (int, http.Header, []byte, error) {
	var req *http.Request

	var err error

	if len(body) == 0 {
		req, err = http.NewRequest(method, endpoint, nil)
		if err != nil {
			return -1, nil, nil, fmt.Errorf(failCreateRequest, err)
		}
	} else {
		req, err = http.NewRequest(method, endpoint, bytes.NewBuffer(body))
		if err != nil {
			return -1, nil, nil, fmt.Errorf(failCreateRequest, err)
		}
	}

	if addHeadersFunc != nil {
		httpHeaders, errAddHdr := addHeadersFunc(req)
		if errAddHdr != nil {
			return -1, nil, nil, fmt.Errorf("add optional request headers error: %w", errAddHdr)
		}

		if httpHeaders != nil {
			req.Header = httpHeaders.Clone()
		}
	}

	if method == http.MethodPost {
		req.Header.Set("Content-Type", contentTypeApplicationJSON)
	}

	resp, err := c.httpClient.Do(req) //nolint: bodyclose
	if err != nil {
		return -1, nil, nil, fmt.Errorf(failSendRequest, err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return -1, nil, nil, fmt.Errorf(failReadResponseBody, err)
	}

	logger.Debugf(sendRequestLogMsg, method, endpoint,
		resp.StatusCode, respBytes)

	return resp.StatusCode, resp.Header, respBytes, nil
}

func closeReadCloser(respBody io.ReadCloser) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf(failCloseResponseBodyLogMsg, err)
	}
}

func getDocIDFromURL(docURL string) string {
	splitBySlashes := strings.Split(docURL, `/`)
	docIDToRetrieve := splitBySlashes[len(splitBySlashes)-1]

	return docIDToRetrieve
}
