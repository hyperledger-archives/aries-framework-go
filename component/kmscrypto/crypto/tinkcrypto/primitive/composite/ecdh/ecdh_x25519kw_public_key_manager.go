/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

const (
	x25519ECDHKWPublicKeyVersion = 0
	x25519ECDHKWPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey"
)

// common errors.
var errInvalidx25519ECDHKWPublicKey = errors.New("x25519kw_ecdh_public_key_manager: invalid key")

// x25519ECDHKWPublicKeyManager is an implementation of KeyManager interface for X25519 key wrapping.
// It generates new ECDHPublicKey (X25519) keys and produces new instances of ECDHAEADCompositeEncrypt subtle.
type x25519ECDHKWPublicKeyManager struct{}

// Assert that x25519ECDHKWPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*x25519ECDHKWPublicKeyManager)(nil)

// newX25519ECDHKWPublicKeyManager creates a new x25519ECDHKWPublicKeyManager.
func newX25519ECDHKWPublicKeyManager() *x25519ECDHKWPublicKeyManager {
	return new(x25519ECDHKWPublicKeyManager)
}

// Primitive creates an ECDHESXChachaPublicKey subtle for the given serialized ECDHESXChachaPublicKey proto.
func (km *x25519ECDHKWPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidx25519ECDHKWPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPublicKey
	}

	err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_public_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeEncrypt(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *x25519ECDHKWPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == x25519ECDHKWPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *x25519ECDHKWPublicKeyManager) TypeURL() string {
	return x25519ECDHKWPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *x25519ECDHKWPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("x25519kw_ecdh_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *x25519ECDHKWPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("x25519kw_ecdh_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given EcdhAeadPublicKey.
func (km *x25519ECDHKWPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) error {
	err := keyset.ValidateKeyVersion(key.Version, x25519ECDHKWPublicKeyVersion)
	if err != nil {
		return fmt.Errorf("x25519kw_ecdh_public_key_manager: invalid key: %w", err)
	}

	return validateKeyXChachaFormat(key.Params)
}
