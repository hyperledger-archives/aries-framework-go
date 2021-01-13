/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
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
	ecdhX25519XChachaPublicKeyVersion = 0
	ecdhX25519XChachaPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhX25519KwXChachaAeadPublicKey" // nolint:lll
)

// common errors.
var errInvalidECDHX25519XChachaPublicKey = errors.New("ecdh_x25519kw_xchachaaead_public_key_manager: invalid key")

// ecdhX25519XChachaPublicKeyManager is an implementation of KeyManager interface for X25519 key wrapping and
// XChacha20Poly1305 content encryption.
// It generates new ECDHPublicKey (X25519) keys and produces new instances of ECDHAEADCompositeEncrypt subtle.
type ecdhX25519XChachaPublicKeyManager struct{}

// Assert that ecdhX25519XChachaPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*ecdhX25519XChachaPublicKeyManager)(nil)

// newECDHX25519XChachaPublicKeyManager creates a new ecdhX25519XChachaPublicKeyManager.
func newECDHX25519XChachaPublicKeyManager() *ecdhX25519XChachaPublicKeyManager {
	return new(ecdhX25519XChachaPublicKeyManager)
}

// Primitive creates an ECDHESXChachaPublicKey subtle for the given serialized ECDHESXChachaPublicKey proto.
func (km *ecdhX25519XChachaPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHX25519XChachaPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHX25519XChachaPublicKey
	}

	err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHX25519XChachaPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_xchachaaead_public_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeEncrypt(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhX25519XChachaPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhX25519XChachaPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhX25519XChachaPublicKeyManager) TypeURL() string {
	return ecdhX25519XChachaPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *ecdhX25519XChachaPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("ecdh_x25519kw_xchachaaead_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *ecdhX25519XChachaPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("ecdh_x25519kw_xchachaaead_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given EcdhAeadPublicKey.
func (km *ecdhX25519XChachaPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) error {
	err := keyset.ValidateKeyVersion(key.Version, ecdhX25519XChachaPublicKeyVersion)
	if err != nil {
		return fmt.Errorf("ecdh_x25519kw_xchachaaead_public_key_manager: invalid key: %w", err)
	}

	return validateKeyXChachaFormat(key.Params)
}
