/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didconnection

import diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"

// Store stores DIDs indexed by public key, so agents can find the DID associated with a given key.
type Store interface {
	// SaveDID saves a DID indexed by the given public keys to the Store
	SaveDID(did string, keys ...string) error
	// GetDID gets the DID stored under the given key
	GetDID(key string) (string, error)
	// SaveDIDConnection saves a connection between this agent's DID and another agent's DID
	SaveDIDConnection(myDID, theirDID string, theirKeys []string) error
	// SaveDIDByResolving resolves a DID using the VDR then saves the map from keys -> did
	SaveDIDByResolving(did, serviceType, keyType string) error
	// SaveDIDFromDoc saves a map from keys -> did for a did doc
	SaveDIDFromDoc(doc *diddoc.Doc, serviceType, keyType string) error
}
