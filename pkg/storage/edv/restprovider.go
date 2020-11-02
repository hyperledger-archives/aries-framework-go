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

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	indexName                  = "StoreName-FriendlyKeyName"
	indexValueFormat           = "%s-%s"
	contentTypeApplicationJSON = "application/json"
	locationHeaderName         = "Location"

	failComputeMACIndexName               = "failed to compute MAC for index name: %w"
	failComputeMACIndexValue              = "failed to compute index value MAC: %w"
	failCreateIndexedAttribute            = "failed to create indexed attribute: %w"
	failComputeBase64EncodedIndexValueMAC = "failed to compute Base64-encoded index value MAC: %w"
	failCreateDocumentInEDVServer         = "failed to create document in EDV server: %w"
	failQueryVaultInEDVServer             = "failed to query vault in EDV server: %w"
	noDocumentMatchingQueryFound          = "no document matching the query was found: %w"
	failRetrieveDocumentFromEDVServer     = "failed to retrieve document from EDV server: %w"

	failSendGETRequest             = "failed to send GET request: %w"
	failSendPOSTRequest            = "failed to send POST request: %w"
	failReadResponseBody           = "failed to read response body: %w"
	failMarshalQuery               = "failed to marshal query: %w"
	failResponseFromEDVServer      = "status code %d was returned along with the following message: %s"
	failUnmarshalDocumentLocations = "failed to unmarshal response bytes into document locations: %w"

	createDocumentRequestLogMsg = "Sending request to create the following document: %s"
	sendGETRequestLogMsg        = `Sent GET request to %s.
Response status code: %d
Response body: %s`
	sendPOSTRequestLogMsg = `Sent POST request to %s.
Request body: %s

Response status code: %d
Response body: %s`
	failCloseResponseBodyLogMsg = "Failed to close response body: %s"
)

var (
	logger                            = log.New("EDV-REST-Provider")
	errDeleteNotSupported             = errors.New("EDV REST store delete functionality not yet implemented")
	errMultipleDocumentsMatchingQuery = errors.New("multiple documents matching the query were found." +
		"This probably indicates an issue with the EDV server's database")
)

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

// RESTProvider is a store provider that can be used to store data in a server supporting the
// data vault HTTPS API as defined in https://identity.foundation/secure-data-store/#data-vault-https-api.
type RESTProvider struct {
	vaultID                  string
	macCrypto                *MACCrypto
	indexKeyMACBase64Encoded string
	restClient               restClient
}

// NewRESTProvider returns a new RESTProvider. edvServerURL is the base URL for the data vault HTTPS API.
// vaultID is the ID of the vault where this provider will store data. The vault must be created in advance, and since
// the EDV REST API does not provide a method to check if a vault with a given ID exists, any errors due to a
// non-existent vault will be deferred until calls are actually made to it in the restStore.
// macCrypto is used to create an encrypted indices, which allow for documents to be queries based on a key
// without leaking that key to the EDV server.
func NewRESTProvider(edvServerURL, vaultID string,
	macCrypto *MACCrypto, httpClientOpts ...Option) (*RESTProvider, error) {
	indexKeyMAC, err := macCrypto.ComputeMAC(indexName)
	if err != nil {
		return nil, fmt.Errorf(failComputeMACIndexName, err)
	}

	client := restClient{
		edvServerURL: edvServerURL,
		httpClient:   &http.Client{},
	}

	for _, opt := range httpClientOpts {
		opt(&client)
	}

	return &RESTProvider{
		vaultID:                  vaultID,
		macCrypto:                macCrypto,
		indexKeyMACBase64Encoded: base64.URLEncoding.EncodeToString([]byte(indexKeyMAC)),
		restClient:               client,
	}, nil
}

// OpenStore opens a new restStore, using name as the namespace.
func (r *RESTProvider) OpenStore(name string) (storage.Store, error) {
	return &restStore{
		vaultID:                  r.vaultID,
		name:                     name,
		macCrypto:                r.macCrypto,
		indexKeyMACBase64Encoded: r.indexKeyMACBase64Encoded,
		restClient:               r.restClient,
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

type restStore struct {
	vaultID                  string
	name                     string
	restClient               restClient
	macCrypto                *MACCrypto
	indexKeyMACBase64Encoded string
}

// v must be a marshalled EncryptedDocument.
func (r *restStore) Put(k string, v []byte) error {
	var encryptedDocument EncryptedDocument

	err := json.Unmarshal(v, &encryptedDocument)
	if err != nil {
		return fmt.Errorf(failUnmarshalValueIntoEncryptedDocument, err)
	}

	indexedAttributeCollection, err := r.createIndexedAttribute(k)
	if err != nil {
		return fmt.Errorf(failCreateIndexedAttribute, err)
	}

	encryptedDocument.IndexedAttributeCollections = indexedAttributeCollection

	_, err = r.restClient.createDocument(r.vaultID, &encryptedDocument)
	if err != nil {
		return fmt.Errorf(failCreateDocumentInEDVServer, err)
	}

	return nil
}

func (r *restStore) Get(k string) ([]byte, error) {
	indexValueMACBase64Encoded, err := r.computeIndexValueMACBase64Encoded(k)
	if err != nil {
		return nil, fmt.Errorf(failComputeBase64EncodedIndexValueMAC, err)
	}

	matchingDocumentIDs, err := r.restClient.queryVault(r.vaultID, &Query{
		Name:  r.indexKeyMACBase64Encoded,
		Value: indexValueMACBase64Encoded,
	})
	if err != nil {
		return nil, fmt.Errorf(failQueryVaultInEDVServer, err)
	}

	if len(matchingDocumentIDs) == 0 {
		return nil, fmt.Errorf(noDocumentMatchingQueryFound, storage.ErrDataNotFound)
	} else if len(matchingDocumentIDs) > 1 {
		// This should only be possible if the EDV server is not able to maintain the uniqueness property of the
		// indexedAttribute created in the createIndexedAttribute method.
		// TODO (#2287): Check each of the documents to see if they all have the same content
		// (other than the document ID). If so, we should delete the extras and just return one of them arbitrarily.
		return nil, errMultipleDocumentsMatchingQuery
	}

	encryptedDocumentBytes, err := r.restClient.readDocument(r.vaultID, getDocIDFromURL(matchingDocumentIDs[0]))
	if err != nil {
		return nil, fmt.Errorf(failRetrieveDocumentFromEDVServer, err)
	}

	return encryptedDocumentBytes, nil
}

// Not support by restStore. The EDV data vault HTTPS API doesn't support this type of operation,
// nor is there a feasible way to emulate it. The iterator returned always is always in an error state.
func (r *restStore) Iterator(string, string) storage.StoreIterator {
	return &restStoreIterator{}
}

// TODO (#2286): Implement this.
func (r *restStore) Delete(string) error {
	return errDeleteNotSupported
}

func (r *restStore) createIndexedAttribute(keyName string) ([]IndexedAttributeCollection, error) {
	indexValueMACBase64Encoded, err := r.computeIndexValueMACBase64Encoded(keyName)
	if err != nil {
		return nil, fmt.Errorf(failComputeBase64EncodedIndexValueMAC, err)
	}

	indexedAttribute := IndexedAttribute{
		Name:   r.indexKeyMACBase64Encoded,
		Value:  indexValueMACBase64Encoded,
		Unique: true,
	}

	indexedAttributeCollection := IndexedAttributeCollection{
		HMAC:              IDTypePair{},
		IndexedAttributes: []IndexedAttribute{indexedAttribute},
	}

	indexedAttributeCollections := []IndexedAttributeCollection{indexedAttributeCollection}

	return indexedAttributeCollections, nil
}

func (r *restStore) computeIndexValueMACBase64Encoded(keyName string) (string, error) {
	indexValueMAC, err := r.macCrypto.ComputeMAC(fmt.Sprintf(indexValueFormat, r.name, keyName))
	if err != nil {
		return "", fmt.Errorf(failComputeMACIndexValue, err)
	}

	return base64.URLEncoding.EncodeToString([]byte(indexValueMAC)), nil
}

var errIteratorNotSupported = errors.New("EDV REST store does not support the Iterator method")

// Iterating through a restStore is not supported, so this type always returns an error.
type restStoreIterator struct {
}

func (r *restStoreIterator) Next() bool {
	return false
}

func (r *restStoreIterator) Release() {}

func (r *restStoreIterator) Error() error {
	return errIteratorNotSupported
}

func (r *restStoreIterator) Key() []byte {
	return nil
}

func (r *restStoreIterator) Value() []byte {
	return nil
}

// restClient is used to make HTTP REST calls to a server supporting the
// data vault HTTPS API as defined in https://identity.foundation/secure-data-store/#data-vault-https-api
type restClient struct {
	edvServerURL string
	httpClient   *http.Client
}

// Option configures the EDV client.
type Option func(opts *restClient)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *restClient) {
		opts.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}

// createDocument sends the EDV server a request to store the specified document.
// The location of the newly created document is returned.
func (c *restClient) createDocument(vaultID string, document *EncryptedDocument) (string, error) {
	jsonToSend, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf(failMarshalEncryptedDocument, err)
	}

	logger.Debugf(createDocumentRequestLogMsg, jsonToSend)

	endpoint := fmt.Sprintf("%s/%s/documents", c.edvServerURL, vaultID)

	// The linter falsely claims that the body is not being closed
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := c.httpClient.Post(endpoint, contentTypeApplicationJSON, bytes.NewBuffer(jsonToSend)) //nolint: bodyclose
	if err != nil {
		return "", fmt.Errorf(failSendPOSTRequest, err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf(failReadResponseBody, err)
	}

	logger.Debugf(sendPOSTRequestLogMsg, endpoint, jsonToSend, resp.StatusCode, respBytes)

	if resp.StatusCode == http.StatusCreated {
		return resp.Header.Get(locationHeaderName), nil
	}

	return "", fmt.Errorf(failResponseFromEDVServer, resp.StatusCode, respBytes)
}

// readDocument sends the EDV server a request to retrieve the specified document.
// The requested document, if found, is returned.
func (c *restClient) readDocument(vaultID, docID string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	// The linter falsely claims that the body is not being closed
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := c.httpClient.Get(endpoint) //nolint: bodyclose
	if err != nil {
		return nil, fmt.Errorf(failSendGETRequest, err)
	}

	defer closeReadCloser(resp.Body)

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(failReadResponseBody, err)
	}

	logger.Debugf(sendGETRequestLogMsg, endpoint, resp.StatusCode, respBody)

	switch resp.StatusCode {
	case http.StatusOK:
		return respBody, nil
	default:
		return nil, fmt.Errorf(failResponseFromEDVServer, resp.StatusCode, respBody)
	}
}

// queryVault queries the given vault and returns the URLs of all documents that match the given query.
func (c *restClient) queryVault(vaultID string, query *Query) ([]string, error) {
	jsonToSend, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf(failMarshalQuery, err)
	}

	endpoint := fmt.Sprintf("%s/%s/query", c.edvServerURL, url.PathEscape(vaultID))

	// The linter falsely claims that the body is not being closed
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := c.httpClient.Post(endpoint, contentTypeApplicationJSON, //nolint: bodyclose
		bytes.NewBuffer(jsonToSend))
	if err != nil {
		return nil, fmt.Errorf(failSendPOSTRequest, err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(failReadResponseBody, err)
	}

	logger.Debugf(sendPOSTRequestLogMsg, endpoint, jsonToSend, resp.StatusCode, respBytes)

	if resp.StatusCode == http.StatusOK {
		var docLocations []string

		err = json.Unmarshal(respBytes, &docLocations)
		if err != nil {
			return nil, fmt.Errorf(failUnmarshalDocumentLocations, err)
		}

		return docLocations, nil
	}

	return nil, fmt.Errorf(failResponseFromEDVServer, resp.StatusCode, respBytes)
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
