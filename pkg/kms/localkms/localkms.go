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

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/bbs"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms/internal/keywrapper"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/store/wrapper/prefix"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Namespace is the keystore's DB storage namespace.
	Namespace = "kmsdb"

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
	store             storage.Store
	primaryKeyEnvAEAD *aead.KMSEnvelopeAEAD
}

func newKeyIDWrapperStore(provider storage.Provider, storePrefix string) (storage.Store, error) {
	s, err := provider.OpenStore(storePrefix + Namespace)
	if err != nil {
		return nil, err
	}

	return prefix.NewPrefixStoreWrapper(s, prefix.StorageKIDPrefix)
}

// New will create a new (local) KMS service.
func New(primaryKeyURI string, p kms.Provider) (*LocalKMS, error) {
	return NewWithPrefix(primaryKeyURI, p, "")
}

// NewWithPrefix will create a new (local) KMS service using a store name prefixed with storePrefix.
func NewWithPrefix(primaryKeyURI string, p kms.Provider, storePrefix string) (*LocalKMS, error) {
	store, err := newKeyIDWrapperStore(p.StorageProvider(), storePrefix)
	if err != nil {
		return nil, fmt.Errorf("new: failed to ceate local kms: %w", err)
	}

	secretLock := p.SecretLock()

	kw, err := keywrapper.New(secretLock, primaryKeyURI)
	if err != nil {
		return nil, fmt.Errorf("new: failed to create new keywrapper: %w", err)
	}

	// create a KMSEnvelopeAEAD instance to wrap/unwrap keys managed by LocalKMS
	keyEnvelopeAEAD := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kw)

	return &LocalKMS{
			store:             store,
			secretLock:        secretLock,
			primaryKeyURI:     primaryKeyURI,
			primaryKeyEnvAEAD: keyEnvelopeAEAD,
		},
		nil
}

// Create a new key/keyset/key handle for the type kt
// Returns:
//  - keyID of the handle
//  - handle instance (to private key)
//  - error if failure
func (l *LocalKMS) Create(kt kms.KeyType) (string, interface{}, error) {
	if kt == "" {
		return "", nil, fmt.Errorf("failed to create new key, missing key type")
	}

	keyTemplate, err := getKeyTemplate(kt)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to getKeyTemplate: %w", err)
	}

	kh, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to create new keyset handle: %w", err)
	}

	kID, err := l.storeKeySet(kh, kt)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to store keyset: %w", err)
	}

	return kID, kh, nil
}

// Get key handle for the given keyID
// Returns:
//  - handle instance (to private key)
//  - error if failure
func (l *LocalKMS) Get(keyID string) (interface{}, error) {
	return l.getKeySet(keyID)
}

// Rotate a key referenced by keyID and return a new handle of a keyset including old key and
// new key with type kt. It also returns the updated keyID as the first return value
// Returns:
//  - new KeyID
//  - handle instance (to private key)
//  - error if failure
func (l *LocalKMS) Rotate(kt kms.KeyType, keyID string) (string, interface{}, error) {
	kh, err := l.getKeySet(keyID)
	if err != nil {
		return "", nil, fmt.Errorf("rotate: failed to getKeySet: %w", err)
	}

	keyTemplate, err := getKeyTemplate(kt)
	if err != nil {
		return "", nil, fmt.Errorf("rotate: failed to get getKeyTemplate: %w", err)
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

// nolint:gocyclo
func getKeyTemplate(keyType kms.KeyType) (*tinkpb.KeyTemplate, error) {
	switch keyType {
	case kms.AES128GCMType:
		return aead.AES128GCMKeyTemplate(), nil
	case kms.AES256GCMNoPrefixType:
		// RAW (to support keys not generated by Tink)
		return aead.AES256GCMNoPrefixKeyTemplate(), nil
	case kms.AES256GCMType:
		return aead.AES256GCMKeyTemplate(), nil
	case kms.ChaCha20Poly1305Type:
		return aead.ChaCha20Poly1305KeyTemplate(), nil
	case kms.XChaCha20Poly1305Type:
		return aead.XChaCha20Poly1305KeyTemplate(), nil
	case kms.ECDSAP256TypeDER:
		return signature.ECDSAP256KeyWithoutPrefixTemplate(), nil
	case kms.ECDSAP384TypeDER:
		return signature.ECDSAP384KeyWithoutPrefixTemplate(), nil
	case kms.ECDSAP521TypeDER:
		return signature.ECDSAP521KeyWithoutPrefixTemplate(), nil
	case kms.ECDSAP256TypeIEEEP1363:
		// JWS keys should sign using IEEE_P1363 format only (not DER format)
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256), nil
	case kms.ECDSAP384TypeIEEEP1363:
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA384, commonpb.EllipticCurveType_NIST_P384), nil
	case kms.ECDSAP521TypeIEEEP1363:
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA512, commonpb.EllipticCurveType_NIST_P521), nil
	case kms.ED25519Type:
		return signature.ED25519KeyWithoutPrefixTemplate(), nil
	case kms.HMACSHA256Tag256Type:
		return mac.HMACSHA256Tag256KeyTemplate(), nil
	case kms.NISTP256ECDHKWType:
		return ecdh.NISTP256ECDHKWKeyTemplate(), nil
	case kms.NISTP384ECDHKWType:
		return ecdh.NISTP384ECDHKWKeyTemplate(), nil
	case kms.NISTP521ECDHKWType:
		return ecdh.NISTP521ECDHKWKeyTemplate(), nil
	case kms.X25519ECDHKWType:
		return ecdh.X25519ECDHKWKeyTemplate(), nil
	case kms.BLS12381G2Type:
		return bbs.BLS12381G2KeyTemplate(), nil
	default:
		return nil, fmt.Errorf("getKeyTemplate: key type '%s' unrecognized", keyType)
	}
}

func createECDSAIEEE1363KeyTemplate(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *tinkpb.KeyTemplate {
	params := &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
	}
	format := &ecdsapb.EcdsaKeyFormat{Params: params}
	serializedFormat, _ := proto.Marshal(format) //nolint:errcheck

	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdsaPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}

func (l *LocalKMS) storeKeySet(kh *keyset.Handle, kt kms.KeyType) (string, error) {
	var (
		kid string
		err error
	)

	switch kt {
	case kms.AES128GCMType, kms.AES256GCMType, kms.AES256GCMNoPrefixType, kms.ChaCha20Poly1305Type,
		kms.XChaCha20Poly1305Type, kms.HMACSHA256Tag256Type:
		// symmetric keys will have random kid value (generated in the local storeWriter)
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
		return writeToStore(l.store, buf, kms.WithKeyID(kid))
	}

	return writeToStore(l.store, buf)
}

func writeToStore(store storage.Store, buf *bytes.Buffer, opts ...kms.PrivateKeyOpts) (string, error) {
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
//  - marshalled public key []byte
//  - error if it fails to export the public key bytes
func (l *LocalKMS) ExportPubKeyBytes(id string) ([]byte, error) {
	kh, err := l.getKeySet(id)
	if err != nil {
		return nil, fmt.Errorf("exportPubKeyBytes: failed to get keyset handle: %w", err)
	}

	marshalledKey, err := l.exportPubKeyBytes(kh)
	if err != nil {
		return nil, fmt.Errorf("exportPubKeyBytes: failed to export marshalled key: %w", err)
	}

	return setKIDForCompositeKey(marshalledKey, id)
}

func setKIDForCompositeKey(marshalledKey []byte, kid string) ([]byte, error) {
	pubKey := &cryptoapi.PublicKey{}

	err := json.Unmarshal(marshalledKey, pubKey)
	if err != nil { // if unmarshalling to VerificationMethod fails, it's not a composite key, return original bytes
		return marshalledKey, nil
	}

	pubKey.KID = kid

	return json.Marshal(pubKey)
}

func (l *LocalKMS) exportPubKeyBytes(kh *keyset.Handle) ([]byte, error) {
	// kh must be a private asymmetric key in order to extract its public key
	pubKH, err := kh.Public()
	if err != nil {
		return nil, fmt.Errorf("exportPubKeyBytes: failed to get public keyset handle: %w", err)
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, fmt.Errorf("exportPubKeyBytes: failed to create keyset with no secrets (public "+
			"key material): %w", err)
	}

	return buf.Bytes(), nil
}

// CreateAndExportPubKeyBytes will create a key of type kt and export its public key in raw bytes and returns it.
// The key must be an asymmetric key.
// Returns:
//  - keyID of the new handle created.
//  - marshalled public key []byte
//  - error if it fails to export the public key bytes
func (l *LocalKMS) CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error) {
	kid, _, err := l.Create(kt)
	if err != nil {
		return "", nil, fmt.Errorf("createAndExportPubKeyBytes: failed to create new key: %w", err)
	}

	pubKeyBytes, err := l.ExportPubKeyBytes(kid)
	if err != nil {
		return "", nil, fmt.Errorf("createAndExportPubKeyBytes: failed to export new public key bytes: %w", err)
	}

	return kid, pubKeyBytes, nil
}

// PubKeyBytesToHandle will create and return a key handle for pubKey of type kt
// it returns an error if it failed creating the key handle
// Note: The key handle created is not stored in the KMS, it's only useful to execute the crypto primitive
// associated with it.
func (l *LocalKMS) PubKeyBytesToHandle(pubKey []byte, kt kms.KeyType) (interface{}, error) {
	return publicKeyBytesToHandle(pubKey, kt)
}

// ImportPrivateKey will import privKey into the KMS storage for the given keyType then returns the new key id and
// the newly persisted Handle.
// 'privKey' possible types are: *ecdsa.PrivateKey and ed25519.PrivateKey
// 'keyType' possible types are signing key types only (ECDSA keys or Ed25519)
// 'opts' allows setting the keysetID of the imported key using WithKeyID() option. If the ID is already used,
// then an error is returned.
// Returns:
//  - keyID of the handle
//  - handle instance (to private key)
//  - error if import failure (key empty, invalid, doesn't match keyType, unsupported keyType or storing key failed)
func (l *LocalKMS) ImportPrivateKey(privKey interface{}, kt kms.KeyType,
	opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
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

func (l *LocalKMS) generateKID(kh *keyset.Handle, kt kms.KeyType) (string, error) {
	keyBytes, err := l.exportPubKeyBytes(kh)
	if err != nil {
		return "", fmt.Errorf("generateKID: failed to export public key: %w", err)
	}

	return CreateKID(keyBytes, kt)
}
