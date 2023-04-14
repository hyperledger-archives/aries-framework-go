/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"

	kmsservice "github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// KeyManager mocks a local Key Management Service + ExportableKeyManager.
type KeyManager struct {
	CreateKeyID              string
	CreateKeyValue           *keyset.Handle
	CreateKeyErr             error
	CreateKeyFn              func(kt kms.KeyType) (string, interface{}, error)
	GetKeyValue              *keyset.Handle
	GetKeyErr                error
	RotateKeyID              string
	RotateKeyValue           *keyset.Handle
	RotateKeyErr             error
	ExportPubKeyBytesErr     error
	ExportPubKeyBytesValue   []byte
	ExportPubKeyTypeValue    kms.KeyType
	CrAndExportPubKeyValue   []byte
	CrAndExportPubKeyID      string
	CrAndExportPubKeyErr     error
	PubKeyBytesToHandleErr   error
	PubKeyBytesToHandleValue *keyset.Handle
	ImportPrivateKeyErr      error
	ImportPrivateKeyID       string
	ImportPrivateKeyValue    *keyset.Handle
}

// Create a new mock ey/keyset/key handle for the type kt.
func (k *KeyManager) Create(kt kms.KeyType, opts ...kms.KeyOpts) (string, interface{}, error) {
	if k.CreateKeyErr != nil {
		return "", nil, k.CreateKeyErr
	}

	if k.CreateKeyFn != nil {
		return k.CreateKeyFn(kt)
	}

	return k.CreateKeyID, k.CreateKeyValue, nil
}

// Get a mock key handle for the given keyID.
func (k *KeyManager) Get(keyID string) (interface{}, error) {
	if k.GetKeyErr != nil {
		return nil, k.GetKeyErr
	}

	return k.GetKeyValue, nil
}

// Rotate returns a mocked rotated keyset handle and its ID.
func (k *KeyManager) Rotate(kt kms.KeyType, keyID string,
	opts ...kms.KeyOpts) (string, interface{}, error) {
	if k.RotateKeyErr != nil {
		return "", nil, k.RotateKeyErr
	}

	return k.RotateKeyID, k.RotateKeyValue, nil
}

// ExportPubKeyBytes will return a mocked []bytes public key.
func (k *KeyManager) ExportPubKeyBytes(keyID string) ([]byte, kms.KeyType, error) {
	if k.ExportPubKeyBytesErr != nil {
		return nil, "", k.ExportPubKeyBytesErr
	}

	return k.ExportPubKeyBytesValue, k.ExportPubKeyTypeValue, nil
}

// CreateAndExportPubKeyBytes return a mocked kid and []byte public key.
func (k *KeyManager) CreateAndExportPubKeyBytes(kt kms.KeyType,
	opts ...kms.KeyOpts) (string, []byte, error) {
	if k.CrAndExportPubKeyErr != nil {
		return "", nil, k.CrAndExportPubKeyErr
	}

	return k.CrAndExportPubKeyID, k.CrAndExportPubKeyValue, nil
}

// PubKeyBytesToHandle will return a mocked keyset.Handle representing a public key handle.
func (k *KeyManager) PubKeyBytesToHandle(pubKey []byte, keyType kms.KeyType,
	opts ...kms.KeyOpts) (interface{}, error) {
	if k.PubKeyBytesToHandleErr != nil {
		return nil, k.PubKeyBytesToHandleErr
	}

	return k.PubKeyBytesToHandleValue, nil
}

// ImportPrivateKey will emulate importing a private key and returns a mocked keyID, private key handle.
func (k *KeyManager) ImportPrivateKey(privKey interface{}, keyType kms.KeyType,
	opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
	if k.ImportPrivateKeyErr != nil {
		return "", nil, k.ImportPrivateKeyErr
	}

	return k.ImportPrivateKeyID, k.ImportPrivateKeyValue, nil
}

func createMockKeyHandle(ks *tinkpb.Keyset) (*keyset.Handle, error) {
	primaryKey := ks.Key[0]

	if primaryKey.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
		return nil, fmt.Errorf("expect a non-raw key")
	}

	return testkeyset.NewHandle(ks)
}

// CreateMockAESGCMKeyHandle is a utility function that returns a mock key (for tests only, not registered in Tink).
func CreateMockAESGCMKeyHandle() (*keyset.Handle, error) {
	ks := testutil.NewTestAESGCMKeyset(tinkpb.OutputPrefixType_TINK)

	return createMockKeyHandle(ks)
}

// CreateMockED25519KeyHandle is a utility function that returns a mock key (for tests only, not registered in Tink).
func CreateMockED25519KeyHandle() (*keyset.Handle, error) {
	serializedKey, err := proto.Marshal(testutil.NewED25519PrivateKey())
	if err != nil {
		return nil, err
	}

	ks := testutil.NewTestKeyset(testutil.NewKeyData(testutil.ED25519SignerTypeURL, serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE), tinkpb.OutputPrefixType_TINK)

	return createMockKeyHandle(ks)
}

// Provider provides mock Provider implementation.
type Provider struct {
	storeProvider kms.Store
	secretLock    secretlock.Service
}

// StorageProvider return a storage provider.
func (p *Provider) StorageProvider() kms.Store {
	return p.storeProvider
}

// SecretLock returns a secret lock service.
func (p *Provider) SecretLock() secretlock.Service {
	return p.secretLock
}

// NewProviderForKMS creates a new mock Provider to create a KMS.
func NewProviderForKMS(storeProvider storage.Provider, secretLock secretlock.Service) (*Provider, error) {
	kmsStore, err := kmsservice.NewAriesProviderWrapper(storeProvider)
	if err != nil {
		return nil, err
	}

	return &Provider{
		storeProvider: kmsStore,
		secretLock:    secretLock,
	}, nil
}
