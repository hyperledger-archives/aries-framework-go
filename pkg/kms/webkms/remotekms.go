/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	spi "github.com/hyperledger/aries-framework-go/spi/log"
)

const (
	// KeystoreEndpoint represents a remote keystore endpoint with swappable {serverEndpoint} value.
	KeystoreEndpoint = "{serverEndpoint}/kms/keystores"

	// ContentType is remoteKMS http content-type.
	ContentType = "application/json"

	// LocationHeader is remoteKMS http header set by the key server (usually to identify a keystore or key url).
	LocationHeader = "Location"
	// XRootCapabilityHeader defines XRootCapability header.
	XRootCapabilityHeader = "X-ROOTCAPABILITY"
)

var logger = log.New("aries-framework/kms/webkms")

// HTTPClient interface for the http client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type createKeystoreReq struct {
	Controller string `json:"controller,omitempty"`
	VaultID    string `json:"vaultID,omitempty"`
}

type createKeyReq struct {
	KeyType   string `json:"keyType,omitempty"`
	ExportKey bool   `json:"export,omitempty"`
}

type createResp struct {
	Location string `json:"location,omitempty"`
	KeyBytes string `json:"publicKey,omitempty"`
}

type exportKeyResp struct {
	KeyBytes string `json:"publicKey,omitempty"`
}

type importKeyReq struct {
	KeyBytes string `json:"keyBytes,omitempty"`
	KeyType  string `json:"keyType,omitempty"`
	KeyID    string `json:"keyID,omitempty"`
}

type importKeyResp struct {
	Location string `json:"location,omitempty"`
}

type marshalFunc func(interface{}) ([]byte, error)

type unmarshalFunc func([]byte, interface{}) error

// RemoteKMS implementation of kms.KeyManager api.
type RemoteKMS struct {
	httpClient    HTTPClient
	keystoreURL   string
	marshalFunc   marshalFunc
	unmarshalFunc unmarshalFunc
	opts          *Opts
}

// CreateKeyStore calls the key server's create keystore REST function and returns the resulting keystoreURL value.
// Arguments of this function are described below:
//   - httpClient used to POST the request
//   - keyserverURL representing the key server url
//	 - marshaller the marshal function used for marshaling content in the client. Usually: `json.Marshal`
//   - headersOpt optional function setting any necessary http headers for key server authorization
// Returns:
//  - keystore URL (if successful)
//  - error (if error encountered)
func CreateKeyStore(httpClient HTTPClient, keyserverURL, controller, vaultID string,
	opts ...Opt) (string, string, error) {
	createKeyStoreStart := time.Now()
	kOpts := NewOpt()

	for _, opt := range opts {
		opt(kOpts)
	}

	destination := strings.ReplaceAll(KeystoreEndpoint, "{serverEndpoint}", keyserverURL)
	httpReqJSON := &createKeystoreReq{
		Controller: controller,
	}

	if vaultID != "" {
		httpReqJSON.VaultID = vaultID
	}

	mReq, err := kOpts.marshal(httpReqJSON)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal Create keystore request [%s, %w]", destination, err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, destination, bytes.NewBuffer(mReq))
	if err != nil {
		return "", "", fmt.Errorf("build request for Create keystore error: %w", err)
	}

	httpReq.Header.Set("Content-Type", ContentType)

	if kOpts.HeadersFunc != nil {
		httpHeaders, e := kOpts.HeadersFunc(httpReq)
		if e != nil {
			return "", "", fmt.Errorf("add optional request headers error: %w", e)
		}

		if httpHeaders != nil {
			httpReq.Header = httpHeaders.Clone()
		}
	}

	start := time.Now()

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", "", fmt.Errorf("posting Create keystore failed [%s, %w]", destination, err)
	}

	logger.Infof("call of CreateStore http request duration: %s", time.Since(start))

	// handle response
	defer closeResponseBody(resp.Body, logger, "CreateKeyStore")

	keystoreURL := resp.Header.Get(LocationHeader)
	capability := resp.Header.Get(XRootCapabilityHeader)

	logger.Infof("overall CreateStore duration: %s", time.Since(createKeyStoreStart))

	return keystoreURL, capability, nil
}

// New creates a new remoteKMS instance using http client connecting to keystoreURL.
func New(keystoreURL string, client HTTPClient, opts ...Opt) *RemoteKMS {
	kOpts := NewOpt()

	for _, opt := range opts {
		opt(kOpts)
	}

	return &RemoteKMS{
		httpClient:    client,
		keystoreURL:   keystoreURL,
		marshalFunc:   json.Marshal,
		unmarshalFunc: json.Unmarshal,
		opts:          kOpts,
	}
}

func (r *RemoteKMS) postHTTPRequest(destination string, mReq []byte) (*http.Response, error) {
	return r.doHTTPRequest(http.MethodPost, destination, mReq)
}

func (r *RemoteKMS) getHTTPRequest(destination string) (*http.Response, error) {
	return r.doHTTPRequest(http.MethodGet, destination, nil)
}

func (r *RemoteKMS) doHTTPRequest(method, destination string, mReq []byte) (*http.Response, error) {
	start := time.Now()

	var (
		httpReq *http.Request
		err     error
	)

	if mReq != nil {
		httpReq, err = http.NewRequest(method, destination, bytes.NewBuffer(mReq))
		if err != nil {
			return nil, fmt.Errorf("build post request error: %w", err)
		}
	} else {
		httpReq, err = http.NewRequest(method, destination, nil)
		if err != nil {
			return nil, fmt.Errorf("build get request error: %w", err)
		}
	}

	if method == http.MethodPost {
		httpReq.Header.Set("Content-Type", ContentType)
	}

	if r.opts.HeadersFunc != nil {
		httpHeaders, e := r.opts.HeadersFunc(httpReq)
		if e != nil {
			return nil, fmt.Errorf("add optional request headers error: %w", e)
		}

		if httpHeaders != nil {
			httpReq.Header = httpHeaders.Clone()
		}
	}

	resp, err := r.httpClient.Do(httpReq)

	logger.Infof("  HTTP %s %s call duration: %s", method, destination, time.Since(start))

	return resp, err
}

// Create a new key/keyset/key handle for the type kt remotely
// Returns:
//  - KeyID raw ID of the handle
//  - handle instance representing a remote keystore URL including KeyID
//  - error if failure
func (r *RemoteKMS) Create(kt kms.KeyType) (string, interface{}, error) {
	startCreate := time.Now()

	keyURL, _, err := r.createKey(kt, false)
	if err != nil {
		return "", nil, err
	}

	kid := keyURL[strings.LastIndex(keyURL, "/")+1:]

	logger.Infof("overall Create key duration: %s", time.Since(startCreate))

	return kid, keyURL, nil
}

func (r *RemoteKMS) createKey(kt kms.KeyType, exportKey bool) (string, []byte, error) {
	destination := r.keystoreURL + "/keys"

	httpReqJSON := &createKeyReq{
		KeyType:   string(kt),
		ExportKey: exportKey,
	}

	marshaledReq, err := r.marshalFunc(httpReqJSON)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal Create key request [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, marshaledReq)
	if err != nil {
		return "", nil, fmt.Errorf("posting Create key failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "Create")

	keyURL := resp.Header.Get(LocationHeader)

	if keyURL != "" && !exportKey {
		return keyURL, nil, nil
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("read key response for Create failed [%s, %w]", destination, err)
	}

	var httpResp createResp

	err = r.unmarshalFunc(respBody, &httpResp)
	if err != nil {
		return "", nil, fmt.Errorf("unmarshal key for Create failed [%s, %w]", destination, err)
	}

	if keyURL == "" {
		keyURL = httpResp.Location
	}

	keyBytes, err := base64.URLEncoding.DecodeString(httpResp.KeyBytes)
	if err != nil {
		return "", nil, err
	}

	return keyURL, keyBytes, nil
}

// Get key handle for the given KeyID remotely
// Returns:
//  - handle instance representing a remote keystore URL including KeyID
//  - error if failure
func (r *RemoteKMS) Get(keyID string) (interface{}, error) {
	return r.buildKIDURL(keyID), nil
}

func (r *RemoteKMS) buildKIDURL(keyID string) string {
	return r.keystoreURL + "/keys/" + keyID
}

// Rotate remotely a key referenced by KeyID and return a new handle of a keyset including old key and
// new key with type kt. It also returns the updated KeyID as the first return value
// Returns:
//  - new KeyID
//  - handle instance (to private key)
//  - error if failure
func (r *RemoteKMS) Rotate(kt kms.KeyType, keyID string) (string, interface{}, error) {
	return "", nil, errors.New("function Rotate is not implemented in remoteKMS")
}

// ExportPubKeyBytes will remotely fetch a key referenced by id then gets its public key in raw bytes and returns it.
// The key must be an asymmetric key.
// Returns:
//  - marshalled public key []byte
//  - error if it fails to export the public key bytes
func (r *RemoteKMS) ExportPubKeyBytes(keyID string) ([]byte, error) {
	startExport := time.Now()
	keyURL := r.buildKIDURL(keyID)

	destination := keyURL + "/export"

	resp, err := r.getHTTPRequest(destination)
	if err != nil {
		return nil, fmt.Errorf("posting GET ExportPubKeyBytes key failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "ExportPubKeyBytes")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read key response for ExportPubKeyBytes failed [%s, %w]", destination, err)
	}

	httpResp := &exportKeyResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal key for ExportPubKeyBytes failed [%s, %w]", destination, err)
	}

	keyBytes, err := base64.URLEncoding.DecodeString(httpResp.KeyBytes)
	if err != nil {
		return nil, err
	}

	logger.Infof("overall ExportPubKeyBytes duration: %s", time.Since(startExport))

	return keyBytes, nil
}

// CreateAndExportPubKeyBytes will remotely create a key of type kt and export its public key in raw bytes and returns
// it. The key must be an asymmetric key.
// Returns:
//  - KeyID of the new handle created.
//  - marshalled public key []byte
//  - error if it fails to export the public key bytes
func (r *RemoteKMS) CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error) {
	start := time.Now()

	keyURL, keyBytes, err := r.createKey(kt, true)
	if err != nil {
		return "", nil, err
	}

	kid := keyURL[strings.LastIndex(keyURL, "/")+1:]

	logger.Infof("overall CreateAndExportPubKeyBytes duration: %s", time.Since(start))

	return kid, keyBytes, nil
}

// PubKeyBytesToHandle is not implemented in remoteKMS.
func (r *RemoteKMS) PubKeyBytesToHandle(pubKey []byte, kt kms.KeyType) (interface{}, error) {
	return nil, errors.New("function PubKeyBytesToHandle is not implemented in remoteKMS")
}

// ImportPrivateKey will import privKey into the KMS storage for the given KeyType then returns the new key id and
// the newly persisted Handle.
// 'privKey' possible types are: *ecdsa.PrivateKey and ed25519.PrivateKey
// 'kt' possible types are signing key types only (ECDSA keys or Ed25519)
// 'opts' allows setting the keysetID of the imported key using WithKeyID() option. If the ID is already used,
// then an error is returned.
// Returns:
//  - KeyID of the handle
//  - handle instance (to private key)
//  - error if import failure (key empty, invalid, doesn't match KeyType, unsupported KeyType or storing key failed)
func (r *RemoteKMS) ImportPrivateKey(privKey interface{}, kt kms.KeyType,
	opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
	pOpts := kms.NewOpt()

	for _, opt := range opts {
		opt(pOpts)
	}

	destination := r.keystoreURL + "/import"

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	httpReqJSON := &importKeyReq{
		KeyBytes: base64.URLEncoding.EncodeToString(keyBytes),
		KeyType:  string(kt),
		KeyID:    pOpts.KsID(),
	}

	marshaledReq, err := r.marshalFunc(httpReqJSON)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal ImportKey request [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, marshaledReq)
	if err != nil {
		return "", nil, fmt.Errorf("failed to post ImportKey request [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "ImportPrivateKey")

	keyURL := resp.Header.Get(LocationHeader)

	if keyURL == "" {
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", nil, fmt.Errorf("failed to read response for ImportKey [%s, %w]", destination, err)
		}

		var httpResp importKeyResp

		err = r.unmarshalFunc(respBody, &httpResp)
		if err != nil {
			return "", nil, fmt.Errorf("failed to unmarshal response body for ImportKey [%s, %w]", destination, err)
		}

		keyURL = httpResp.Location
	}

	kid := keyURL[strings.LastIndex(keyURL, "/")+1:]

	return kid, keyURL, nil
}

// closeResponseBody closes the response body.
//nolint: interfacer // don't want to add test stretcher logger here
func closeResponseBody(respBody io.Closer, logger spi.Logger, action string) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body for '%s' REST call: %s", action, err.Error())
	}
}
