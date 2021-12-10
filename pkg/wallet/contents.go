/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bluele/gcache"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// ContentType is wallet content type.
type ContentType string

const (
	// Collection content type which can be used to group wallet contents together.
	// https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
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

const (
	// collectionMappingKeyPrefix is db name space for saving collection ID to wallet content mappings.
	collectionMappingKeyPrefix = "collectionmapping"
)

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

type storeOpenHandle func(string) (storage.Store, error)

type storeCloseHandle func() error

// default store handles for content store.
//nolint:gochecknoglobals
var (
	storeLocked storeOpenHandle = func(string) (storage.Store, error) {
		return nil, ErrWalletLocked
	}

	noOp = func() error { return nil }
)

// contentStore is store for wallet contents for given user profile.
type contentStore struct {
	storeID  string
	provider *storageProvider
	open     storeOpenHandle
	close    storeCloseHandle
	lock     sync.RWMutex
}

// newContentStore returns new wallet content store instance.
// will use underlying storage provider as content storage if profile doesn't have edv settings.
func newContentStore(p storage.Provider, pr *profile) *contentStore {
	contents := &contentStore{open: storeLocked, close: noOp, provider: newWalletStorageProvider(pr, p), storeID: pr.ID}

	if store, err := storeManager().get(pr.ID); err == nil {
		contents.updateStoreHandles(store)
	}

	return contents
}

func (cs *contentStore) Open(auth string, opts *unlockOpts) error {
	store, err := cs.provider.OpenStore(auth, opts, storage.StoreConfiguration{TagNames: []string{
		Collection.Name(), Credential.Name(), Connection.Name(), DIDResolutionResponse.Name(), Connection.Name(), Key.Name(),
	}})
	if err != nil {
		return err
	}

	// store instances needs to be cached to share unlock session between multiple instances of wallet.
	if err := storeManager().persist(cs.storeID, store, opts.tokenExpiry); err != nil {
		return err
	}

	cs.lock.Lock()
	defer cs.lock.Unlock()

	cs.updateStoreHandles(store)

	return nil
}

func (cs *contentStore) updateStoreHandles(store storage.Store) {
	// give access to store only when auth is valid & not expired.
	cs.open = func(auth string) (storage.Store, error) {
		_, err := keyManager().getKeyManger(auth)
		if err != nil {
			return nil, ErrInvalidAuthToken
		}

		return store, nil
	}

	cs.close = func() error {
		return store.Close()
	}
}

func (cs *contentStore) Close() bool {
	cs.lock.Lock()
	defer cs.lock.Unlock()

	if err := cs.close(); err != nil {
		logger.Debugf("failed to close wallet content store: %s", err)
	}

	cs.open = storeLocked
	cs.close = noOp

	return storeManager().delete(cs.storeID)
}

// Save for storing given wallet content to store by content ID (content document id) & content type.
// if content document id is missing from content, then system generated id will be used as key for storage.
// returns error if content with same ID already exists in store.
// For replacing already existing content, use 'Remove() + Add()'.
func (cs *contentStore) Save(auth string, ct ContentType, content []byte, options ...AddContentOptions) error {
	opts := &addContentOpts{}

	for _, option := range options {
		option(opts)
	}

	switch ct {
	case Collection, Metadata, Connection, Credential:
		key, err := getContentID(content)
		if err != nil {
			return err
		}

		err = cs.mapCollection(auth, key, opts.collectionID, ct)
		if err != nil {
			return err
		}

		return cs.safeSave(auth, getContentKeyPrefix(ct, key), content, storage.Tag{Name: ct.Name()})
	case DIDResolutionResponse:
		// verify did resolution result before storing and also use DID ID as content key
		docRes, err := did.ParseDocumentResolution(content)
		if err != nil {
			return fmt.Errorf("invalid DID resolution response model: %w", err)
		}

		err = cs.mapCollection(auth, docRes.DIDDocument.ID, opts.collectionID, ct)
		if err != nil {
			return err
		}

		return cs.safeSave(auth, getContentKeyPrefix(ct, docRes.DIDDocument.ID), content, storage.Tag{Name: ct.Name()})
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
func (cs *contentStore) safeSave(auth, key string, content []byte, tags ...storage.Tag) error {
	cs.lock.RLock()
	defer cs.lock.RUnlock()

	store, err := cs.open(auth)
	if err != nil {
		return err
	}

	_, err = store.Get(key)
	if errors.Is(err, storage.ErrDataNotFound) {
		return store.Put(key, content, tags...)
	} else if err != nil {
		return err
	}

	return errors.New("content with same type and id already exists in this wallet")
}

// mapCollection maps given collection to given content.
func (cs *contentStore) mapCollection(auth, key, collectionID string, ct ContentType) error {
	if collectionID == "" {
		return nil
	}

	cs.lock.RLock()
	defer cs.lock.RUnlock()

	store, err := cs.open(auth)
	if err != nil {
		return err
	}

	_, err = store.Get(getContentKeyPrefix(Collection, collectionID))
	if err != nil {
		return fmt.Errorf("failed to find existing collection with ID '%s' : %w", collectionID, err)
	}

	// collection IDs can contain ':' characters which can not be supported by tags.
	return store.Put(getCollectionMappingKeyPrefix(key), []byte(ct.Name()),
		storage.Tag{Name: base64.StdEncoding.EncodeToString([]byte(collectionID))})
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
func (cs *contentStore) Remove(auth, key string, ct ContentType) error {
	cs.lock.RLock()
	defer cs.lock.RUnlock()

	store, err := cs.open(auth)
	if err != nil {
		return err
	}

	// delete mapping
	err = store.Delete(getCollectionMappingKeyPrefix(key))
	if err != nil {
		return err
	}

	// delete from store
	return store.Delete(getContentKeyPrefix(ct, key))
}

// Get to get wallet content from wallet contents store.
func (cs *contentStore) Get(auth, key string, ct ContentType) ([]byte, error) {
	cs.lock.RLock()
	defer cs.lock.RUnlock()

	store, err := cs.open(auth)
	if err != nil {
		return nil, err
	}

	return store.Get(getContentKeyPrefix(ct, key))
}

// GetAll returns all wallet contents of give type.
// returns empty result when no data found.
func (cs *contentStore) GetAll(auth string, ct ContentType) (map[string]json.RawMessage, error) {
	cs.lock.RLock()
	defer cs.lock.RUnlock()

	store, err := cs.open(auth)
	if err != nil {
		return nil, err
	}

	iter, err := store.Query(ct.Name())
	if err != nil {
		return nil, err
	}

	result := make(map[string]json.RawMessage)

	for {
		ok, err := iter.Next()
		if err != nil {
			return nil, err
		}

		if !ok {
			break
		}

		key, err := iter.Key()
		if err != nil {
			return nil, err
		}

		val, err := iter.Value()
		if err != nil {
			return nil, err
		}

		result[removeKeyPrefix(ct.Name(), key)] = val
	}

	return result, nil
}

// FilterByCollection returns all wallet contents of give type and collection.
// returns empty result when no data found.
func (cs *contentStore) GetAllByCollection(auth,
	collectionID string, ct ContentType) (map[string]json.RawMessage, error) {
	cs.lock.RLock()
	defer cs.lock.RUnlock()

	store, err := cs.open(auth)
	if err != nil {
		return nil, err
	}

	iter, err := store.Query(base64.StdEncoding.EncodeToString([]byte(collectionID)))
	if err != nil {
		return nil, err
	}

	result := make(map[string]json.RawMessage)

	for {
		ok, err := iter.Next()
		if err != nil {
			return nil, err
		}

		if !ok {
			break
		}

		key, err := iter.Key()
		if err != nil {
			return nil, err
		}

		val, err := iter.Value()
		if err != nil {
			return nil, err
		}

		// filter by content type
		if string(val) != ct.Name() {
			continue
		}

		contentKey := removeKeyPrefix(collectionMappingKeyPrefix, key)

		contentVal, err := store.Get(getContentKeyPrefix(ct, contentKey))
		if err != nil {
			return nil, err
		}

		result[contentKey] = contentVal
	}

	return result, nil
}

func getContentID(content []byte) (string, error) {
	var cid contentID
	if err := json.Unmarshal(content, &cid); err != nil {
		return "", fmt.Errorf("failed to read content to be saved : %w", err)
	}

	key := cid.ID
	if strings.TrimSpace(key) == "" {
		// use document hash as key to avoid duplicates if id is missing
		digest := sha256.Sum256(content)
		return hex.EncodeToString(digest[0:]), nil
	}

	return key, nil
}

// getContentKeyPrefix returns key prefix by wallet content type and storage key.
func getContentKeyPrefix(ct ContentType, key string) string {
	return fmt.Sprintf("%s_%s", ct, key)
}

// getCollectionMappingKeyPrefix returns key prefix by wallet collection ID and storage key.
func getCollectionMappingKeyPrefix(key string) string {
	return fmt.Sprintf("%s_%s", collectionMappingKeyPrefix, key)
}

// removeContentKeyPrefix removes content key prefix.
func removeKeyPrefix(prefix, key string) string {
	return strings.Replace(key, fmt.Sprintf("%s_", prefix), "", 1)
}

// newContentBasedVDR returns new wallet content store based VDR.
func newContentBasedVDR(auth string, v vdr.Registry, c *contentStore) *walletVDR {
	return &walletVDR{auth: auth, Registry: v, contents: c}
}

// walletVDR is wallet content based on VDR which tries to resolve DIDs from wallet content store,
// if DID document not found then it falls back to vdr registry.
// Note: For using this has to be unlocked by auth token.
type walletVDR struct {
	vdr.Registry
	contents *contentStore
	auth     string
}

func (v *walletVDR) Resolve(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	docBytes, err := v.contents.Get(v.auth, didID, DIDResolutionResponse)
	if err == nil {
		resolvedDOC, e := did.ParseDocumentResolution(docBytes)
		if e != nil {
			return nil, fmt.Errorf("failed to parse stored DID: %w", e)
		}

		return resolvedDOC, nil
	} else if errors.Is(err, ErrWalletLocked) {
		return nil, err
	}

	return v.Registry.Resolve(didID, opts...)
}

//nolint:gochecknoglobals
var (
	walletStoreInstance *walletStoreManager
	walletStoreOnce     sync.Once
)

func storeManager() *walletStoreManager {
	walletStoreOnce.Do(func() {
		walletStoreInstance = &walletStoreManager{
			gstore: gcache.New(0).Build(),
		}
	})

	return walletStoreInstance
}

// walletStoreManager manages store instances in cache.
// this is store manager singleton - access only via storeManager()
// underlying gcache is threasafe, no need of locks.
type walletStoreManager struct {
	gstore gcache.Cache
}

func (ws *walletStoreManager) persist(id string, store storage.Store, expiration time.Duration) error {
	if expiration == 0 {
		expiration = defaultCacheExpiry
	}

	return ws.gstore.SetWithExpire(id, store, expiration)
}

func (ws *walletStoreManager) get(id string) (storage.Store, error) {
	val, err := ws.gstore.Get(id)
	if err != nil {
		return nil, err
	}

	return val.(storage.Store), nil
}

func (ws *walletStoreManager) delete(id string) bool {
	return ws.gstore.Remove(id)
}
