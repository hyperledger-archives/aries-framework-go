/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/proto/tink_go_proto"

	kmsservice "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// KeyManager mocks a local Key Management Service
type KeyManager struct {
	CreateKeyID    string
	CreateKeyValue *keyset.Handle
	CreateKeyErr   error
	GetKeyValue    *keyset.Handle
	GetKeyErr      error
	RotateKeyID    string
	RotateKeyValue *keyset.Handle
	RotateKeyErr   error
}

// Create a new mock ey/keyset/key handle for the type kt
func (k *KeyManager) Create(kt kmsservice.KeyType) (string, interface{}, error) {
	if k.CreateKeyErr != nil {
		return "", nil, k.CreateKeyErr
	}

	return k.CreateKeyID, k.CreateKeyValue, nil
}

// Get a mock key handle for the given keyID
func (k *KeyManager) Get(keyID string) (interface{}, error) {
	if k.GetKeyErr != nil {
		return nil, k.GetKeyErr
	}

	return k.GetKeyValue, nil
}

// Rotate returns a mocked rotated keyset handle and its ID
func (k *KeyManager) Rotate(kt kmsservice.KeyType, keyID string) (string, interface{}, error) {
	if k.RotateKeyErr != nil {
		return "", nil, k.RotateKeyErr
	}

	return k.RotateKeyID, k.RotateKeyValue, nil
}

// CreateMockKeyHandle is a utility function that returns a mock key (for tests only. ie: not registered in Tink)
func CreateMockKeyHandle() (*keyset.Handle, error) {
	ks := testutil.NewTestAESGCMKeyset(tinkpb.OutputPrefixType_TINK)
	primaryKey := ks.Key[0]

	if primaryKey.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
		return nil, fmt.Errorf("expect a non-raw key")
	}

	return testkeyset.NewHandle(ks)
}

// Provider provides mock Provider implementation.
type Provider struct {
	storeProvider storage.Provider
	secretLock    secretlock.Service
}

// StorageProvider return a storage provider.
func (p *Provider) StorageProvider() storage.Provider {
	return p.storeProvider
}

// SecretLock returns a secret lock service
func (p *Provider) SecretLock() secretlock.Service {
	return p.secretLock
}

// NewProvider creates a new mock Provider.
func NewProvider(storeProvider storage.Provider, secretLock secretlock.Service) *Provider {
	return &Provider{
		storeProvider: storeProvider,
		secretLock:    secretLock,
	}
}
