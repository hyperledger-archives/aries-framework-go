/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didconnection

import (
	"errors"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Store stores DIDs indexed by public key, so agents can find the DID associated with a given key.
type Store interface {
	// SaveDID saves a DID indexed by the given public keys to the Store
	SaveDID(did string, keys ...string) error
	// GetDID gets the DID stored under the given key
	GetDID(key string) (string, error)
	// SaveDIDByResolving resolves a DID using the VDR then saves the map from keys -> did
	SaveDIDByResolving(did string, keys ...string) error
	// SaveDIDFromDoc saves a map from keys -> did for a did doc
	SaveDIDFromDoc(doc *diddoc.Doc) error
}

// ErrNotFound signals that the entry for the given DID and key is not present in the store.
var ErrNotFound = errors.New("did not found under given key")
