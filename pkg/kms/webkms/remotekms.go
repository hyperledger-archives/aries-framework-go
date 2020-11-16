/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// Namespace of the remoteKMS local config storage.
	Namespace = "remotekmsdb"

	// KeystoreURLField representing the user's keystore URL field in the remoteKMS local storage.
	KeystoreURLField = "keystoreurl"

	// ControllerField representing the user's Controller field in the remoteKMS local storage.
	ControllerField = "controller"

	// SecretField representing the user's secret field in the remoteKMS local storage.
	SecretField = "secret"

	createKeystoreEndpoint = "{serverEndpoint}/kms/keystores"

	// ContentType is remoteKMS http content-type.
	ContentType = "application/json"

	// LocationHeader is remoteKMS http header set by the key server (usually to identify a keystore or key url).
	LocationHeader = "Location"

	// KeyBytesHeader is remoteKMS http header set by the key server (to contain an base64URL encoded public key).
	KeyBytesHeader = "KeyBytes"
)

var logger = log.New("aries-framework/kms/webkms")

type createKeystoreReq struct {
	Controller string `json:"controller,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type createKeyReq struct {
	KeyType    string `json:"keytype,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type exportKeyReq struct {
	KeyID      string `json:"keyid,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type marshalFunc func(interface{}) ([]byte, error)

// RemoteKMS implementation of kms.KeyManager api.
type RemoteKMS struct {
	httpClient  *http.Client
	secret      string
	configStore storage.Store
	keystoreURL string
	marshalFunc marshalFunc
}

// New creates a new remoteKMS instance using http client connecting to a server at a url saved in a local remoteKMS
// configuration configStore called as in Namespace const.
// The marshaller function is used to marshal content in the client, it should usually be `json.Marshal`.
func New(provider storage.Provider, client *http.Client, marshaller marshalFunc) (*RemoteKMS, error) {
	configStore, err := provider.OpenStore(Namespace)
	if err != nil {
		return nil, err
	}

	keystoreURL, err := configStore.Get(KeystoreURLField)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keystore url from remoteKMS config storage: %s", err)
	}

	secret, err := configStore.Get(SecretField)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keystore secret from remoteKMS config storage: %s", err)
	}

	return &RemoteKMS{
		httpClient:  client,
		secret:      string(secret),
		configStore: configStore,
		keystoreURL: string(keystoreURL),
		marshalFunc: marshaller,
	}, nil
}

// CreateKeyStore calls the key server's create keystore REST function and saves the resulting keystoreURL value in a
// local remoteKMS configStore.
// Arguments of this function are described below:
//   - configStore is where the keystoreURL, Controller and secret will be stored
//   - httpClient used to POST the request
//   - keyserverURL representing the key server url
//   - Controller is the identifier of the keystore owner (usually a DID key ID)
//   - secret represents the configStore secret for locking/unlocking the keystore
//	 - marshaller the marshal function used for marshaling content in the client. Usually: `json.Marshal`
// Returns:
//  - keystore URL (if successful)
//  - error (if error encountered)
func CreateKeyStore(store storage.Store, httpClient *http.Client, keyserverURL, controller string,
	secret []byte, marshaller marshalFunc) (string, error) {
	destination := strings.ReplaceAll(createKeystoreEndpoint, "{serverEndpoint}", keyserverURL)
	httpReq := &createKeystoreReq{
		Controller: controller,
		Passphrase: base64.URLEncoding.EncodeToString(secret),
	}

	req, err := marshaller(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Create keystore request [%s, %w]", destination, err)
	}

	resp, err := httpClient.Post(destination, ContentType, bytes.NewBuffer(req))
	if err != nil {
		return "", fmt.Errorf("posting Create keystore failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "CreateKeyStore")

	keystoreURL := resp.Header.Get(LocationHeader)

	err = store.Put(KeystoreURLField, []byte(keystoreURL))
	if err != nil {
		return "", fmt.Errorf("failed to save keystoreURL in remoteKMS configStore: %w", err)
	}

	// the following can be stored earlier, but storing them after keystoreURL to ensure it was created
	err = store.Put(ControllerField, []byte(controller))
	if err != nil {
		return "", fmt.Errorf("failed to save Controller in remoteKMS configStore: %w", err)
	}

	err = store.Put(SecretField, []byte(base64.URLEncoding.EncodeToString(secret)))
	if err != nil {
		return "", fmt.Errorf("failed to save secret in remoteKMS configStore: %w", err)
	}

	return keystoreURL, nil
}

// Create a new key/keyset/key handle for the type kt remotely
// Returns:
//  - KeyID raw ID of the handle
//  - handle instance representing a remote keystore URL including KeyID
//  - error if failure
func (r *RemoteKMS) Create(kt kms.KeyType) (string, interface{}, error) {
	destination := r.keystoreURL + "/keys"
	httpReq := &createKeyReq{
		KeyType:    string(kt),
		Passphrase: r.secret,
	}

	req, err := r.marshalFunc(httpReq)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal Create key request [%s, %w]", destination, err)
	}

	resp, err := r.httpClient.Post(destination, ContentType, bytes.NewBuffer(req))
	if err != nil {
		return "", nil, fmt.Errorf("posting Create key failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "Create")

	kidURL := resp.Header.Get(LocationHeader)
	kid := kidURL[strings.LastIndex(kidURL, "/")+1:]

	return kid, kidURL, nil
}

// Get key handle for the given KeyID remotely
// Returns:
//  - handle instance representing a remote keystore URL including KeyID
//  - error if failure
func (r *RemoteKMS) Get(keyID string) (interface{}, error) {
	return r.buildKIDURL(keyID)
}

func (r *RemoteKMS) buildKIDURL(keyID string) (string, error) {
	keystoreURL, err := r.configStore.Get(KeystoreURLField)
	if err != nil {
		return "", err
	}

	return string(keystoreURL) + "/keys/" + keyID, nil
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
	keyURL, err := r.buildKIDURL(keyID)
	if err != nil {
		return nil, err
	}

	destination := keyURL + "/export"

	httpReq := &exportKeyReq{
		KeyID:      keyID,
		Passphrase: r.secret,
	}

	req, err := r.marshalFunc(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ExportPubKeyBytes key request [%s, %w]", destination, err)
	}

	resp, err := r.httpClient.Post(destination, ContentType, bytes.NewBuffer(req))
	if err != nil {
		return nil, fmt.Errorf("posting ExportPubKeyBytes key failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "ExportPubKeyBytes")

	keyBytes, err := base64.URLEncoding.DecodeString(resp.Header.Get(KeyBytesHeader))
	if err != nil {
		return nil, err
	}

	return keyBytes, nil
}

// CreateAndExportPubKeyBytes will remotely create a key of type kt and export its public key in raw bytes and returns
// it. The key must be an asymmetric key.
// Returns:
//  - KeyID of the new handle created.
//  - marshalled public key []byte
//  - error if it fails to export the public key bytes
func (r *RemoteKMS) CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error) {
	kid, _, err := r.Create(kt)
	if err != nil {
		return "", nil, err
	}

	pubKey, err := r.ExportPubKeyBytes(kid)
	if err != nil {
		return "", nil, err
	}

	return kid, pubKey, nil
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
	return "", nil, errors.New("function ImportPrivateKey is not implemented in remoteKMS")
}

// closeResponseBody closes the response body.
//nolint: interfacer // don't want to add test stretcher logger here
func closeResponseBody(respBody io.Closer, logger log.Logger, action string) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body for '%s' REST call: %s", action, err.Error())
	}
}
