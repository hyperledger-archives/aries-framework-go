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

// BaseDIDConnectionStore stores DIDs indexed by key
type BaseDIDConnectionStore struct {
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
func New(ctx provider) (*BaseDIDConnectionStore, error) {
	store, err := ctx.StorageProvider().OpenStore("con-store")
	if err != nil {
		return nil, err
	}

	return &BaseDIDConnectionStore{store: store, vdr: ctx.VDRIRegistry()}, nil
}

// saveDID saves a DID, indexed using the given public key
func (c *BaseDIDConnectionStore) saveDID(did, key string) error {
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
func (c *BaseDIDConnectionStore) SaveDID(did string, keys ...string) error {
	for _, key := range keys {
		err := c.saveDID(did, key)
		if err != nil {
			return fmt.Errorf("saving DID in did map: %w", err)
		}
	}

	return nil
}

// SaveDIDFromDoc saves a map from a did doc's keys to the did
func (c *BaseDIDConnectionStore) SaveDIDFromDoc(doc *diddoc.Doc, serviceType, keyType string) error {
	keys, ok := diddoc.LookupRecipientKeys(doc, serviceType, keyType)
	if !ok {
		return fmt.Errorf("getting DID doc keys")
	}

	return c.SaveDID(doc.ID, keys...)
}

// SaveDIDByResolving resolves a DID using the VDR then saves the map from keys -> did
func (c *BaseDIDConnectionStore) SaveDIDByResolving(did, serviceType, keyType string) error {
	doc, err := c.vdr.Resolve(did)
	if err != nil {
		return err
	}

	return c.SaveDIDFromDoc(doc, serviceType, keyType)
}

// GetDID gets the DID stored under the given key
func (c *BaseDIDConnectionStore) GetDID(key string) (string, error) {
	bytes, err := c.store.Get(key)
	if err != nil {
		return "", err
	}

	var record didRecord

	err = json.Unmarshal(bytes, &record)
	if err != nil {
		return "", err
	}

	return record.DID, nil
}

func (c *BaseDIDConnectionStore) resolvePublicKeys(id string) ([]string, error) {
	doc, err := c.vdr.Resolve(id)
	if err != nil {
		return nil, err
	}

	var keys []string

	for i := range doc.PublicKey {
		keys = append(keys, string(doc.PublicKey[i].Value))
	}

	return keys, nil
}

// SaveDIDConnection saves a connection between this agent's did and another agent
func (c *BaseDIDConnectionStore) SaveDIDConnection(myDID, theirDID string, theirKeys []string) error {
	var keys []string

	keys, err := c.resolvePublicKeys(theirDID)
	if errors.Is(err, vdri.ErrNotFound) {
		keys = theirKeys
	} else if err != nil {
		return err
	}

	// map their pub keys -> their DID
	err = c.SaveDID(theirDID, keys...)
	if err != nil {
		return err
	}

	// map their DID -> my DID
	err = c.SaveDID(myDID, theirDID)
	if err != nil {
		return fmt.Errorf("save DID in did map: %w", err)
	}

	return nil
}
