/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
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

	// Key content type for handling key data models.
	// https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
	Key ContentType = "key"
)

// IsValid checks if underlying content type is supported.
func (ct ContentType) IsValid() error {
	switch ct {
	case Collection, Credential, DIDResolutionResponse, Metadata, Connection, Key:
		return nil
	}

	return fmt.Errorf("invalid content type '%s', supported types are %s", ct,
		[]ContentType{Collection, Credential, DIDResolutionResponse, Metadata, Connection, Key})
}

// Name of the content type.
func (ct ContentType) Name() string {
	return string(ct)
}

// keyContent is wallet content for key type
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
type keyContent struct {
	ID               string          `json:"id"`
	KeyType          string          `json:"type"`
	PrivateKeyJwk    json.RawMessage `json:"privateKeyJwk"`
	PrivateKeyBase58 string          `json:"privateKeyBase58"`
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
		Collection.Name(), Credential.Name(), Connection.Name(), DIDResolutionResponse.Name(), Connection.Name(), Key.Name(),
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store config for user '%s' : %w", pr.User, err)
	}

	return &contentStore{store: store}, nil
}

// Save for storing given wallet content to store by content ID (content document id) & content type.
// if content document id is missing from content, then system generated id will be used as key for storage.
// returns error if content with same ID already exists in store.
// For replacing already existing content, use 'Remove() + Add()'.
func (cs *contentStore) Save(auth string, ct ContentType, content []byte) error {
	switch ct {
	case Collection, Metadata, Connection, Credential:
		key, err := getContentID(content)
		if err != nil {
			return err
		}

		return cs.safeSave(getContentKeyPrefix(ct, key), content, storage.Tag{Name: ct.Name()})
	case DIDResolutionResponse:
		// verify did resolution result before storing and also use DID ID as content key
		docRes, err := did.ParseDocumentResolution(content)
		if err != nil {
			return fmt.Errorf("invalid DID resolution response model: %w", err)
		}

		return cs.safeSave(getContentKeyPrefix(ct, docRes.DIDDocument.ID), content, storage.Tag{Name: ct.Name()})
	case Key:
		// never save keys in store, just import them into kms
		var key keyContent

		err := json.Unmarshal(content, &key)
		if err != nil {
			return fmt.Errorf("failed to read key contents: %w", err)
		}

		return saveKey(auth, &key)
	default:
		return fmt.Errorf("invalid content type '%s', supported types are %s", ct,
			[]ContentType{Collection, Credential, DIDResolutionResponse, Metadata, Connection, Key})
	}
}

// safeSave saves given content to store by given key but returns error if content with given key already exists.
func (cs *contentStore) safeSave(key string, content []byte, tags ...storage.Tag) error {
	_, err := cs.store.Get(key)
	if errors.Is(err, storage.ErrDataNotFound) {
		return cs.store.Put(key, content, tags...)
	} else if err != nil {
		return err
	}

	return errors.New("content with same type and id already exists in this wallet")
}

func saveKey(auth string, key *keyContent) error {
	if len(key.PrivateKeyJwk) > 0 {
		err := importKeyJWK(auth, key)
		if err != nil {
			return fmt.Errorf("failed to import private key jwk: %w", err)
		}
	}

	if key.PrivateKeyBase58 != "" {
		err := importKeyBase58(auth, key)
		if err != nil {
			return fmt.Errorf("failed to import private key base58: %w", err)
		}
	}

	return nil
}

// Remove to remove wallet content from wallet contents store.
func (cs *contentStore) Remove(ct ContentType, key string) error {
	return cs.store.Delete(getContentKeyPrefix(ct, key))
}

// Get to get wallet content from wallet contents store.
func (cs *contentStore) Get(ct ContentType, key string) ([]byte, error) {
	return cs.store.Get(getContentKeyPrefix(ct, key))
}

func getContentID(content []byte) (string, error) {
	var cid contentID
	if err := json.Unmarshal(content, &cid); err != nil {
		return "", fmt.Errorf("failed to read content to be saved : %w", err)
	}

	key := cid.ID
	if strings.TrimSpace(key) == "" {
		return uuid.New().String(), nil
	}

	return key, nil
}

// getContentKeyPrefix returns key prefix by wallet content type and storage key.
func getContentKeyPrefix(ct ContentType, key string) string {
	return fmt.Sprintf("%s_%s", ct, key)
}

// newContentBasedVDR returns new wallet content store based VDR.
func newContentBasedVDR(v vdr.Registry, c *contentStore) *walletVDR {
	return &walletVDR{Registry: v, contents: c}
}

// walletVDR is wallet content based on VDR which tries to resolve DIDs from wallet content store,
// if not found then it falls back to vdr registry.
type walletVDR struct {
	vdr.Registry
	contents *contentStore
}

func (v *walletVDR) Resolve(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	docBytes, err := v.contents.Get(DIDResolutionResponse, didID)
	if err == nil {
		resolvedDOC, err := did.ParseDocumentResolution(docBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse stored DID: %w", err)
		}

		return resolvedDOC, nil
	}

	return v.Registry.Resolve(didID, opts...)
}
