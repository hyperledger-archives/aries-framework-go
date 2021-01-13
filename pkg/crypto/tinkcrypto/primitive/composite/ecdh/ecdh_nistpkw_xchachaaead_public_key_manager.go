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
	ecdhNISTPXChachaPublicKeyVersion = 0
	ecdhNISTPXChachaPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhNistPKwXChachaAeadPublicKey" // nolint:lll
)

// common errors.
var errInvalidECDHNISTPXChachaPublicKey = errors.New("ecdh_nistpkw_xchachaaead_public_key_manager: invalid key")

// ecdhNISTPXChachaPublicKeyManager is an implementation of KeyManager interface for NIST P curved key wrapping and
// XChacha20Poly1305 content encryption.
// It generates new ECDHPublicKey (X25519) keys and produces new instances of ECDHAEADCompositeEncrypt subtle.
type ecdhNISTPXChachaPublicKeyManager struct{}

// Assert that ecdhNISTPXChachaPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*ecdhNISTPXChachaPublicKeyManager)(nil)

// newECDHNISTPXChachaPublicKeyManager creates a new ecdhNISTPXChachaPublicKeyManager.
func newECDHNISTPXChachaPublicKeyManager() *ecdhNISTPXChachaPublicKeyManager {
	return new(ecdhNISTPXChachaPublicKeyManager)
}

// Primitive creates an ECDHESPublicKey subtle for the given serialized ECDHESPublicKey proto.
func (km *ecdhNISTPXChachaPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHNISTPXChachaPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHNISTPXChachaPublicKey
	}

	_, err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHNISTPXChachaPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_xchachaaead_public_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeEncrypt(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhNISTPXChachaPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhNISTPXChachaPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhNISTPXChachaPublicKeyManager) TypeURL() string {
	return ecdhNISTPXChachaPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *ecdhNISTPXChachaPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("ecdh_nistpkw_xchachaaead_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *ecdhNISTPXChachaPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("ecdh_nistpkw_xchachaaead_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given EcdhAeadPublicKey.
func (km *ecdhNISTPXChachaPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhNISTPXChachaPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_xchachaaead_public_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.Params)
}
