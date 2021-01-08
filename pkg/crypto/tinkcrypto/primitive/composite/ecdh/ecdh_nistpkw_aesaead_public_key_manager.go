/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

const (
	ecdhNISTPAESPublicKeyVersion = 0
	ecdhNISTPAESPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhNistPKwAesAeadPublicKey"
)

// common errors.
var errInvalidECDHNISTPAESPublicKey = errors.New("ecdh_nistpkw_aesaead_public_key_manager: invalid key")

// ecdhNISTPAESPublicKeyManager is an implementation of KeyManager interface for NIST P curved key wrapping and
// AES-GCM content encryption.
// It generates new ECDHPublicKey (AES) keys and produces new instances of ECDHAEADCompositeEncrypt subtle.
type ecdhNISTPAESPublicKeyManager struct{}

// Assert that ecdhNISTPAESPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*ecdhNISTPAESPublicKeyManager)(nil)

// newECDHNISTPAESPublicKeyManager creates a new ecdhNISTPAESPublicKeyManager.
func newECDHNISTPAESPublicKeyManager() *ecdhNISTPAESPublicKeyManager {
	return new(ecdhNISTPAESPublicKeyManager)
}

// Primitive creates an ECDHESPublicKey subtle for the given serialized ECDHESPublicKey proto.
func (km *ecdhNISTPAESPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHNISTPAESPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHNISTPAESPublicKey
	}

	_, err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHNISTPAESPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_public_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeEncrypt(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhNISTPAESPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhNISTPAESPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhNISTPAESPublicKeyManager) TypeURL() string {
	return ecdhNISTPAESPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *ecdhNISTPAESPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("ecdh_nistpkw_aesaead_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *ecdhNISTPAESPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("ecdh_nistpkw_aesaead_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given EcdhAeadPublicKey.
func (km *ecdhNISTPAESPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhNISTPAESPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_public_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.Params)
}
