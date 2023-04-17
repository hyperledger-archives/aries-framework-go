/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/webkms"
)

const (
	// KeystoreEndpoint represents a remote keystore endpoint with swappable {serverEndpoint} value.
	KeystoreEndpoint = "{serverEndpoint}/v1/keystores"

	// ContentType is remoteKMS http content-type.
	ContentType = "application/json"
)

// HTTPClient interface for the http client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type marshalFunc = webkms.MarshalFunc

// RemoteKMS implementation of kms.KeyManager api.
type RemoteKMS = webkms.RemoteKMS

// CreateKeyStore calls the key server's create keystore REST function and returns the resulting keystoreURL value.
// Arguments of this function are described below:
//   - httpClient used to POST the request
//   - keyserverURL representing the key server url
//   - marshaller the marshal function used for marshaling content in the client. Usually: `json.Marshal`
//   - headersOpt optional function setting any necessary http headers for key server authorization
//
// Returns:
//   - keystore URL (if successful)
//   - error (if error encountered)
func CreateKeyStore(httpClient HTTPClient, keyserverURL, controller, vaultURL string, // nolint: funlen
	capability []byte, opts ...Opt) (string, []byte, error) {
	return webkms.CreateKeyStore(httpClient, keyserverURL, controller, vaultURL, capability, opts...)
}

// New creates a new remoteKMS instance using http client connecting to keystoreURL.
func New(keystoreURL string, client HTTPClient, opts ...Opt) *RemoteKMS {
	return webkms.New(keystoreURL, client, opts...)
}
