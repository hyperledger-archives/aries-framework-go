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
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// StoreName DID connection store name.
const StoreName = "didconnection"

// ErrNotFound signals that the entry for the given DID and key is not present in the store.
var ErrNotFound = errors.New("did not found under given key")

// ConnectionStore provides interface for storing and retrieving DIDs.
type ConnectionStore interface {
	GetDID(key string) (string, error)
	SaveDID(did string, keys ...string) error
	SaveDIDFromDoc(doc *diddoc.Doc) error
	SaveDIDByResolving(did string, keys ...string) error
}

// ConnectionStoreImpl stores DIDs indexed by key.
type ConnectionStoreImpl struct {
	store storage.Store
	vdr   vdr.Registry
}

type didRecord struct {
	DID string `json:"did,omitempty"`
	// TODO add type below to distinguish Legacy vs new Packer
	// envelopeType string
}

type connectionProvider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
}

// NewConnectionStore returns a new ConnectionStore backed by provided storage and VDR.
func NewConnectionStore(ctx connectionProvider) (*ConnectionStoreImpl, error) {
	store, err := ctx.StorageProvider().OpenStore(StoreName)
	if err != nil {
		return nil, err
	}

	return &ConnectionStoreImpl{store: store, vdr: ctx.VDRegistry()}, nil
}

// saveDID saves a DID, indexed using the given public key.
func (c *ConnectionStoreImpl) saveDID(did, key string) error {
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
func (c *ConnectionStoreImpl) SaveDID(did string, keys ...string) error {
	for _, key := range keys {
		err := c.saveDID(did, key)
		if err != nil {
			return fmt.Errorf("saving DID in did map: %w", err)
		}
	}

	return nil
}

// SaveDIDFromDoc saves a map from a did doc's keys to the did.
func (c *ConnectionStoreImpl) SaveDIDFromDoc(doc *diddoc.Doc) error {
	var keys []string
	for i := range doc.VerificationMethod {
		// TODO fix hardcode base58 https://github.com/hyperledger/aries-framework-go/issues/1207
		// keeping these keys base58 encoded as long as legacyPacker exists
		keys = append(keys, base58.Encode(doc.VerificationMethod[i].Value))
	}

	// assumption doc.KeyAgreement exists when separate encryption keys and verifications keys are used for this DID
	// eg: used by Authcrypt/Anoncrypt Packer (not Legacy Packer)
	for i := range doc.KeyAgreement {
		// add proper crypto keys (as opposed to verification keys as doc.VerificationMethod above)
		keys = append(keys, doc.KeyAgreement[i].VerificationMethod.ID[1:])
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
func (c *ConnectionStoreImpl) SaveDIDByResolving(did string, keys ...string) error {
	docResolution, err := c.vdr.Resolve(did)
	if errors.Is(err, vdr.ErrNotFound) {
		return c.SaveDID(did, keys...)
	} else if err != nil {
		return fmt.Errorf("failed to read from vdr store : %w", err)
	}

	return c.SaveDIDFromDoc(docResolution.DIDDocument)
}

// GetDID gets the DID stored under the given key.
func (c *ConnectionStoreImpl) GetDID(key string) (string, error) {
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
