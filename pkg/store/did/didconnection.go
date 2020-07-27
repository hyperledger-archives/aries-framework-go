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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// StoreName DID connection store name.
const StoreName = "didconnection"

// ErrNotFound signals that the entry for the given DID and key is not present in the store.
var ErrNotFound = errors.New("did not found under given key")

// ConnectionStore stores DIDs indexed by key.
type ConnectionStore struct {
	store storage.Store
	vdr   vdri.Registry
}

type didRecord struct {
	DID string `json:"did,omitempty"`
	// TODO add type below to distinguish Legacy vs new Packer
	// envelopeType string
}

type connectionProvider interface {
	StorageProvider() storage.Provider
	VDRIRegistry() vdri.Registry
}

// NewConnectionStore returns a new did lookup ConnectionStore.
func NewConnectionStore(ctx connectionProvider) (*ConnectionStore, error) {
	store, err := ctx.StorageProvider().OpenStore(StoreName)
	if err != nil {
		return nil, err
	}

	return &ConnectionStore{store: store, vdr: ctx.VDRIRegistry()}, nil
}

// saveDID saves a DID, indexed using the given public key.
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

// SaveDID saves a DID, indexed using the given public keys.
func (c *ConnectionStore) SaveDID(did string, keys ...string) error {
	for _, key := range keys {
		err := c.saveDID(did, key)
		if err != nil {
			return fmt.Errorf("saving DID in did map: %w", err)
		}
	}

	return nil
}

// SaveDIDFromDoc saves a map from a did doc's keys to the did.
func (c *ConnectionStore) SaveDIDFromDoc(doc *diddoc.Doc) error {
	var keys []string
	for i := range doc.PublicKey {
		// TODO fix hardcode base58 https://github.com/hyperledger/aries-framework-go/issues/1207
		keys = append(keys, base58.Encode(doc.PublicKey[i].Value))
	}

	// save recipientKeys from didcomm-enabled service entries
	// an error is returned only if the doc does not have a valid didcomm service entry, so we ignore it
	svc, err := service.CreateDestination(doc)
	if err == nil {
		keys = append(keys, svc.RecipientKeys...)
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
		return fmt.Errorf("failed to read from vdri store : %w", err)
	}

	return c.SaveDIDFromDoc(doc)
}

// GetDID gets the DID stored under the given key.
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
