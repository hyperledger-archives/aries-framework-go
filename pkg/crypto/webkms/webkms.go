/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"github.com/trustbloc/kms-go/crypto/webkms"

	webkmsimpl "github.com/trustbloc/kms-go/kms/webkms"
)

// HTTPClient interface for the http client.
type HTTPClient = webkms.HTTPClient

// RemoteCrypto implementation of kms.KeyManager api.
type RemoteCrypto = webkms.RemoteCrypto

// New creates a new remoteCrypto instance using http client connecting to keystoreURL.
func New(keystoreURL string, client HTTPClient, opts ...webkmsimpl.Opt) *RemoteCrypto {
	return webkms.New(keystoreURL, client, opts...)
}
