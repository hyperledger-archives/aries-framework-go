/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// ContentType is wallet content type.
type ContentType string

const (
	// Collection content type which can be used to group wallet contents together.
	// https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
	Collection ContentType = "collection"

	// Credential content type for handling credential data models.
	// https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
	Credential ContentType = "credential"

	// DIDResolutionResponse content type for handling DID document data models.
	// https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
	DIDResolutionResponse ContentType = "didResolutionResponse"

	// Metadata content type for handling wallet metadata data models.
	// https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
	Metadata ContentType = "metadata"

	// Connection content type for handling wallet connection data models.
	// https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
	Connection ContentType = "connection"
)

// IsValid checks if underlying content type is supported.
func (ct ContentType) IsValid() error {
	switch ct {
	case Collection, Credential, DIDResolutionResponse, Metadata, Connection:
		return nil
	}

	return fmt.Errorf("invalid content type '%s', supported types are %s", ct,
		[]ContentType{Collection, Credential, DIDResolutionResponse, Metadata, Connection})
}

// Name of the content type.
func (ct ContentType) Name() string {
	return string(ct)
}

type contentID struct {
	ID string `json:"id"`
}

// contentStore is store for wallet contents for given user profile.
type contentStore struct {
	store storage.Store
}

// newContentStore returns new wallet content store instance.
func newContentStore(p storage.Provider, pr *profile) (*contentStore, error) {
	store, err := p.OpenStore(pr.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to create store for user '%s' : %w", pr.User, err)
	}

	err = p.SetStoreConfig(pr.ID, storage.StoreConfiguration{TagNames: []string{
		Collection.Name(), Credential.Name(), Connection.Name(), DIDResolutionResponse.Name(), Connection.Name(),
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store config for user '%s' : %w", pr.User, err)
	}

	return &contentStore{store: store}, nil
}

// Save for storing given wallet content to store by content ID & content type.
func (cs *contentStore) Save(ct ContentType, content []byte) error {
	if err := ct.IsValid(); err != nil {
		return err
	}

	var cid contentID
	if err := json.Unmarshal(content, &cid); err != nil {
		return fmt.Errorf("failed to read content to be saved : %w", err)
	}

	if strings.TrimSpace(cid.ID) == "" {
		return errors.New("invalid wallet content, missing 'id' field")
	}

	return cs.store.Put(getContentKeyPrefix(ct, cid.ID), content, storage.Tag{Name: ct.Name()})
}

// Remove to remove wallet content from wallet contents store.
func (cs *contentStore) Remove(ct ContentType, key string) error {
	return cs.store.Delete(getContentKeyPrefix(ct, key))
}

// Get to get wallet content from wallet contents store.
func (cs *contentStore) Get(ct ContentType, key string) ([]byte, error) {
	return cs.store.Get(getContentKeyPrefix(ct, key))
}

// getContentKeyPrefix returns key prefix by wallet content type and storage key.
func getContentKeyPrefix(ct ContentType, key string) string {
	return fmt.Sprintf("%s_%s", ct, key)
}
