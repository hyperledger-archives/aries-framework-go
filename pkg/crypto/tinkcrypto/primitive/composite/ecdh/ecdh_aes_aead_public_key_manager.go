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
	ecdhAESPublicKeyVersion = 0
	ecdhAESPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhAesAeadPublicKey"
)

// common errors.
var errInvalidECDHAESPublicKey = errors.New("ecdh_aes_public_key_manager: invalid key")

// ecdhPublicKeyManager is an implementation of KeyManager interface.
// It generates new ECDHPublicKey (AES) keys and produces new instances of ECDHAEADCompositeEncrypt subtle.
type ecdhPublicKeyManager struct{}

// Assert that ecdhPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*ecdhPublicKeyManager)(nil)

// newECDHPublicKeyManager creates a new ecdhPublicKeyManager.
func newECDHPublicKeyManager() *ecdhPublicKeyManager {
	return new(ecdhPublicKeyManager)
}

// Primitive creates an ECDHESPublicKey subtle for the given serialized ECDHESPublicKey proto.
func (km *ecdhPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHAESPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHAESPublicKey
	}

	_, err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHAESPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_aes_public_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeEncrypt(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhAESPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhPublicKeyManager) TypeURL() string {
	return ecdhAESPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *ecdhPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("ecdh_aes_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *ecdhPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("ecdh_aes_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given ECDHESPublicKey.
func (km *ecdhPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhAESPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdh_aes_publie_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.Params)
}
