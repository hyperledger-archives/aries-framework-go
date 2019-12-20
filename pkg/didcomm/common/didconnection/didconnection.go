/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconnection

import (
	"encoding/json"
	"errors"
	"fmt"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// ConnectionStore stores DIDs indexed by key
type ConnectionStore struct {
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
func New(ctx provider) (*ConnectionStore, error) {
	store, err := ctx.StorageProvider().OpenStore("didconnection")
	if err != nil {
		return nil, err
	}

	return &ConnectionStore{store: store, vdr: ctx.VDRIRegistry()}, nil
}

// saveDID saves a DID, indexed using the given public key
func (c *ConnectionStore) saveDID(did, key string) error {
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
func (c *ConnectionStore) SaveDID(did string, keys ...string) error {
	for _, key := range keys {
		err := c.saveDID(did, key)
		if err != nil {
			return fmt.Errorf("saving DID in did map: %w", err)
		}
	}

	return nil
}

// SaveDIDFromDoc saves a map from a did doc's keys to the did
func (c *ConnectionStore) SaveDIDFromDoc(doc *diddoc.Doc) error {
	var keys []string
	for i := range doc.PublicKey {
		keys = append(keys, string(doc.PublicKey[i].Value))
	}

	return c.SaveDID(doc.ID, keys...)
}

// SaveDIDByResolving resolves a DID using the VDR then saves the map from keys -> did
//  keys: fallback keys in case the DID can't be resolved
func (c *ConnectionStore) SaveDIDByResolving(did string, keys ...string) error {
	doc, err := c.vdr.Resolve(did)
	if errors.Is(err, vdri.ErrNotFound) {
		return c.SaveDID(did, keys...)
	} else if err != nil {
		return err
	}

	return c.SaveDIDFromDoc(doc)
}

// GetDID gets the DID stored under the given key
func (c *ConnectionStore) GetDID(key string) (string, error) {
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
