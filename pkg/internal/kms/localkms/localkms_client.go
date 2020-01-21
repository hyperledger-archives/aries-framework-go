/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"fmt"
	"strings"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

const (
	localKeyURIPrefix = "local-lock://"
)

// localKMSClient to be used by the framework's default kms instance in order to fetch its underlying
// secretLock instance via GetAEAD() call.
// Note: secretLock service (or GetAEAD() call) is never used directly. It is internally used by Tink
//       for wrapping/unwrapping keys.
type localKMSClient struct {
	keyURIPrefix string
	secretLock   secretlock.Service
}

// NewClient creates a new local KMS client for the given uriPrefix and a local secretLock service
func NewClient(secretLock secretlock.Service, uriPrefix string) (registry.KMSClient, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), localKeyURIPrefix) {
		return nil, fmt.Errorf("uriPrefix must start with %s", localKeyURIPrefix)
	}

	return &localKMSClient{
		keyURIPrefix: uriPrefix,
		secretLock:   secretLock,
	}, nil
}

// Supported true if this client does support keyURI
func (c *localKMSClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.keyURIPrefix)
}

// GetAEAD gets an AEAD backend by keyURI.
func (c *localKMSClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, fmt.Errorf("unsupported keyURI")
	}

	uri := strings.TrimPrefix(keyURI, localKeyURIPrefix)

	return newLocalStorageAEAD(uri, c.secretLock), nil
}
