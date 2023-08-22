/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"

	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/spi/secretlock"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
)

const (
	// Namespace is the store name used when creating a KMS store using kms.NewAriesProviderWrapper.
	// The reason this is here in addition to kms.AriesWrapperStoreName is because
	// the IndexedDB implementation refers to this. FOr the WASM unit tests, the aries-framework-go module import gets
	// replaced with the local version and so in order for both to work correctly, for now we have the constant defined
	// in both places.
	Namespace = kms.AriesWrapperStoreName

	ecdsaPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

var errInvalidKeyType = errors.New("key type is not supported")

// package localkms is the default KMS service implementation of pkg/kms.KeyManager. It uses Tink keys to support the
// default Crypto implementation, pkg/crypto/tinkcrypto, and stores these keys in the format understood by Tink. It also
// uses a secretLock service to protect private key material in the storage.

// LocalKMS implements kms.KeyManager to provide key management capabilities using a local db.
// It uses an underlying secret lock service (default local secretLock) to wrap (encrypt) keys
// prior to storing them.
type LocalKMS struct {
	secretLock        secretlock.Service
	primaryKeyURI     string
	store             kmsapi.Store
	primaryKeyEnvAEAD *aead.KMSEnvelopeAEAD
}

// New will create a new (local) KMS service.
func New(primaryKeyURI string, p kmsapi.Provider) (*LocalKMS, error) {
	secretLock := p.SecretLock()

	kw, err := keywrapper.New(secretLock, primaryKeyURI)
	if err != nil {
		return nil, fmt.Errorf("new: failed to create new keywrapper: %w", err)
	}

	// create a KMSEnvelopeAEAD instance to wrap/unwrap keys managed by LocalKMS
	keyEnvelopeAEAD := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kw)

	return &LocalKMS{
			store:             p.StorageProvider(),
			secretLock:        secretLock,
			primaryKeyURI:     primaryKeyURI,
			primaryKeyEnvAEAD: keyEnvelopeAEAD,
		},
		nil
}

// HealthCheck check kms.
func (l *LocalKMS) HealthCheck() error {
	return nil
}

// Create a new key/keyset/key handle for the type kt
// Returns:
//   - keyID of the handle
//   - handle instance (to private key)
//   - error if failure
func (l *LocalKMS) Create(kt kmsapi.KeyType, opts ...kmsapi.KeyOpts) (string, interface{}, error) {
	if kt == "" {
		return "", nil, fmt.Errorf("failed to create new key, missing key type")
	}

	if kt == kmsapi.ECDSASecp256k1DER {
		return "", nil, fmt.Errorf("create: Unable to create kms key: Secp256K1 is not supported by DER format")
	}

	keyTemplate, err := getKeyTemplate(kt, opts...)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to getKeyTemplate: %w", err)
	}

	kh, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to create new keyset handle: %w", err)
	}

	keyID, err := l.storeKeySet(kh, kt)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to store keyset: %w", err)
	}

	return keyID, kh, nil
}

// Get key handle for the given keyID
// Returns:
//   - handle instance (to private key)
//   - error if failure
func (l *LocalKMS) Get(keyID string) (interface{}, error) {
	return l.getKeySet(keyID)
}

// Rotate a key referenced by keyID and return a new handle of a keyset including old key and
// new key with type kt. It also returns the updated keyID as the first return value
// Returns:
//   - new KeyID
//   - handle instance (to private key)
//   - error if failure
func (l *LocalKMS) Rotate(kt kmsapi.KeyType, keyID string, opts ...kmsapi.KeyOpts) (string, interface{}, error) {
	kh, err := l.getKeySet(keyID)
	if err != nil {
		return "", nil, fmt.Errorf("rotate: failed to getKeySet: %w", err)
	}

	keyTemplate, err := getKeyTemplate(kt, opts...)
	if err != nil {
		return "", nil, fmt.Errorf("rotate: failed to get GetKeyTemplate: %w", err)
	}

	km := keyset.NewManagerFromHandle(kh)

	err = km.Rotate(keyTemplate)
	if err != nil {
		return "", nil, fmt.Errorf("rotate: failed to call Tink's keyManager rotate: %w", err)
	}

	updatedKH, err := km.Handle()
	if err != nil {
		return "", nil, fmt.Errorf("rotate: failed to get kms keyest handle: %w", err)
	}

	err = l.store.Delete(keyID)
	if err != nil {
		return "", nil, fmt.Errorf("rotate: failed to delete entry for kid '%s': %w", keyID, err)
	}

	newID, err := l.storeKeySet(updatedKH, kt)
	if err != nil {
		return "", nil, fmt.Errorf("rotate: failed to store keySet: %w", err)
	}

	return newID, updatedKH, nil
}

func (l *LocalKMS) storeKeySet(kh *keyset.Handle, kt kmsapi.KeyType) (string, error) {
	var (
		kid string
		err error
	)

	switch kt {
	case kmsapi.AES128GCMType, kmsapi.AES256GCMType, kmsapi.AES256GCMNoPrefixType, kmsapi.ChaCha20Poly1305Type,
		kmsapi.XChaCha20Poly1305Type, kmsapi.HMACSHA256Tag256Type, kmsapi.CLMasterSecretType:
		// symmetric keys will have random kid value (generated in the local storeWriter)
	case kmsapi.CLCredDefType:
		// ignoring custom KID generation for the asymmetric CL CredDef
	default:
		// asymmetric keys will use the public key's JWK thumbprint base64URL encoded as kid value
		kid, err = l.generateKID(kh, kt)
		if err != nil && !errors.Is(err, errInvalidKeyType) {
			return "", fmt.Errorf("storeKeySet: failed to generate kid: %w", err)
		}
	}

	buf := new(bytes.Buffer)
	jsonKeysetWriter := keyset.NewJSONWriter(buf)

	err = kh.Write(jsonKeysetWriter, l.primaryKeyEnvAEAD)
	if err != nil {
		return "", fmt.Errorf("storeKeySet: failed to write json key to buffer: %w", err)
	}

	// asymmetric keys are JWK thumbprints of the public key, base64URL encoded stored in kid.
	// symmetric keys will have a randomly generated key ID (where kid is empty)
	if kid != "" {
		return writeToStore(l.store, buf, kmsapi.WithKeyID(kid))
	}

	return writeToStore(l.store, buf)
}

func writeToStore(store kmsapi.Store, buf *bytes.Buffer, opts ...kmsapi.PrivateKeyOpts) (string, error) {
	w := newWriter(store, opts...)

	// write buffer to localstorage
	_, err := w.Write(buf.Bytes())
	if err != nil {
		return "", fmt.Errorf("writeToStore: failed to write buffer to store: %w", err)
	}

	return w.KeysetID, nil
}

func (l *LocalKMS) getKeySet(id string) (*keyset.Handle, error) {
	localDBReader := newReader(l.store, id)

	jsonKeysetReader := keyset.NewJSONReader(localDBReader)

	// Read reads the encrypted keyset handle back from the io.reader implementation
	// and decrypts it using primaryKeyEnvAEAD.
	kh, err := keyset.Read(jsonKeysetReader, l.primaryKeyEnvAEAD)
	if err != nil {
		return nil, fmt.Errorf("getKeySet: failed to read json keyset from reader: %w", err)
	}

	return kh, nil
}

// ExportPubKeyBytes will fetch a key referenced by id then gets its public key in raw bytes and returns it.
// The key must be an asymmetric key.
// Returns:
//   - marshalled public key []byte
//   - error if it fails to export the public key bytes
func (l *LocalKMS) ExportPubKeyBytes(id string) ([]byte, kmsapi.KeyType, error) {
	kh, err := l.getKeySet(id)
	if err != nil {
		return nil, "", fmt.Errorf("exportPubKeyBytes: failed to get keyset handle: %w", err)
	}

	marshalledKey, kt, err := l.exportPubKeyBytes(kh)
	if err != nil {
		return nil, "", fmt.Errorf("exportPubKeyBytes: failed to export marshalled key: %w", err)
	}

	// Ignore KID for CL CredDef keys
	if kt == kmsapi.CLCredDefType {
		return marshalledKey, kt, nil
	}

	mUpdatedKey, err := setKIDForCompositeKey(marshalledKey, id)

	return mUpdatedKey, kt, err
}

func setKIDForCompositeKey(marshalledKey []byte, kid string) ([]byte, error) {
	pubKey := &cryptoapi.PublicKey{}

	err := json.Unmarshal(marshalledKey, pubKey)
	if err != nil { // if unmarshalling to VerificationMethod fails, it's not a composite key, return original bytes
		return marshalledKey, nil //nolint:nilerr
	}

	pubKey.KID = kid

	return json.Marshal(pubKey)
}

func (l *LocalKMS) exportPubKeyBytes(kh *keyset.Handle) ([]byte, kmsapi.KeyType, error) {
	// kh must be a private asymmetric key in order to extract its public key
	pubKH, err := kh.Public()
	if err != nil {
		return nil, "", fmt.Errorf("exportPubKeyBytes: failed to get public keyset handle: %w", err)
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, "", fmt.Errorf("exportPubKeyBytes: failed to create keyset with no secrets (public "+
			"key material): %w", err)
	}

	return buf.Bytes(), pubKeyWriter.KeyType, nil
}

// CreateAndExportPubKeyBytes will create a key of type kt and export its public key in raw bytes and returns it.
// The key must be an asymmetric key.
// Returns:
//   - keyID of the new handle created.
//   - marshalled public key []byte
//   - error if it fails to export the public key bytes
func (l *LocalKMS) CreateAndExportPubKeyBytes(kt kmsapi.KeyType, opts ...kmsapi.KeyOpts) (string, []byte, error) {
	kid, _, err := l.Create(kt, opts...)
	if err != nil {
		return "", nil, fmt.Errorf("createAndExportPubKeyBytes: failed to create new key: %w", err)
	}

	pubKeyBytes, _, err := l.ExportPubKeyBytes(kid)
	if err != nil {
		return "", nil, fmt.Errorf("createAndExportPubKeyBytes: failed to export new public key bytes: %w", err)
	}

	return kid, pubKeyBytes, nil
}

// PubKeyBytesToHandle will create and return a key handle for pubKey of type kt
// it returns an error if it failed creating the key handle
// Note: The key handle created is not stored in the KMS, it's only useful to execute the crypto primitive
// associated with it.
func (l *LocalKMS) PubKeyBytesToHandle(pubKey []byte, kt kmsapi.KeyType, opts ...kmsapi.KeyOpts) (interface{}, error) {
	return PublicKeyBytesToHandle(pubKey, kt, opts...)
}

// ImportPrivateKey will import privKey into the KMS storage for the given keyType then returns the new key id and
// the newly persisted Handle.
// 'privKey' possible types are: *ecdsa.PrivateKey and ed25519.PrivateKey
// 'keyType' possible types are signing key types only (ECDSA keys or Ed25519)
// 'opts' allows setting the keysetID of the imported key using WithKeyID() option. If the ID is already used,
// then an error is returned.
// Returns:
//   - keyID of the handle
//   - handle instance (to private key)
//   - error if import failure (key empty, invalid, doesn't match keyType, unsupported keyType or storing key failed)
func (l *LocalKMS) ImportPrivateKey(privKey interface{}, kt kmsapi.KeyType,
	opts ...kmsapi.PrivateKeyOpts) (string, interface{}, error) {
	switch pk := privKey.(type) {
	case *ecdsa.PrivateKey:
		return l.importECDSAKey(pk, kt, opts...)
	case ed25519.PrivateKey:
		return l.importEd25519Key(pk, kt, opts...)
	case *bbs12381g2pub.PrivateKey:
		return l.importBBSKey(pk, kt, opts...)
	default:
		return "", nil, fmt.Errorf("import private key does not support this key type or key is public")
	}
}

func (l *LocalKMS) generateKID(kh *keyset.Handle, kt kmsapi.KeyType) (string, error) {
	keyBytes, _, err := l.exportPubKeyBytes(kh)
	if err != nil {
		return "", fmt.Errorf("generateKID: failed to export public key: %w", err)
	}

	return jwkkid.CreateKID(keyBytes, kt)
}
