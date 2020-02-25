/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// StoreName DID connection store name
const StoreName = "didconnection"

// ErrNotFound signals that the entry for the given DID and key is not present in the store.
var ErrNotFound = errors.New("did not found under given key")

// Store stores DIDs indexed by key
type Store struct {
	store storage.Store
	vdr   vdri.Registry
}

type didRecord struct {
	DID string `json:"did,omitempty"`
}

type provider interface {
	StorageProvider() storage.Provider
	VDRIRegistry() vdri.Registry
}

// New returns a new did lookup Store
func New(ctx provider) (*Store, error) {
	store, err := ctx.StorageProvider().OpenStore(StoreName)
	if err != nil {
		return nil, err
	}

	return &Store{store: store, vdr: ctx.VDRIRegistry()}, nil
}

// saveDID saves a DID, indexed using the given public key
func (c *Store) saveDID(did, key string) error {
	data := didRecord{
		DID: did,
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return c.store.Put(key, bytes)
}

// SaveDID saves a DID, indexed using the given public keys
func (c *Store) SaveDID(did string, keys ...string) error {
	for _, key := range keys {
		err := c.saveDID(did, key)
		if err != nil {
			return fmt.Errorf("saving DID in did map: %w", err)
		}
	}

	return nil
}

// SaveDIDFromDoc saves a map from a did doc's keys to the did
func (c *Store) SaveDIDFromDoc(doc *diddoc.Doc) error {
	var keys []string
	for i := range doc.PublicKey {
		// TODO fix hardcode base58 https://github.com/hyperledger/aries-framework-go/issues/1207
		keys = append(keys, base58.Encode(doc.PublicKey[i].Value))
	}

	return c.SaveDID(doc.ID, keys...)
}

// SaveDIDByResolving resolves a DID using the VDR then saves the map from keys -> did
//  keys: fallback keys in case the DID can't be resolved
func (c *Store) SaveDIDByResolving(did string, keys ...string) error {
	doc, err := c.vdr.Resolve(did)
	if errors.Is(err, vdri.ErrNotFound) {
		return c.SaveDID(did, keys...)
	} else if err != nil {
		return err
	}

	return c.SaveDIDFromDoc(doc)
}

// GetDID gets the DID stored under the given key
func (c *Store) GetDID(key string) (string, error) {
	bytes, err := c.store.Get(key)
	if errors.Is(err, storage.ErrDataNotFound) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}

	var record didRecord

	err = json.Unmarshal(bytes, &record)
	if err != nil {
		return "", err
	}

	return record.DID, nil
}
