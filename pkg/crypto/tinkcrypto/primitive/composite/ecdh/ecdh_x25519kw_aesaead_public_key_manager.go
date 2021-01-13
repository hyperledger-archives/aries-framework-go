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
	ecdhX25519AESPublicKeyVersion = 0
	ecdhX25519AESPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhX25519KwAesAeadPublicKey"
)

// common errors.
var errInvalidECDHX25519AESPublicKey = errors.New("ecdh_x25519kw_aesaead_public_key_manager: invalid key")

// ecdhX25519AESPublicKeyManager is an implementation of KeyManager interface for X25519 key wrapping and
// AES20Poly1305 content encryption.
// It generates new ECDHPublicKey (X25519) keys and produces new instances of ECDHAEADCompositeEncrypt subtle.
type ecdhX25519AESPublicKeyManager struct{}

// Assert that ecdhX25519AESPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*ecdhX25519AESPublicKeyManager)(nil)

// newECDHX25519AESPublicKeyManager creates a new ecdhX25519AESPublicKeyManager.
func newECDHX25519AESPublicKeyManager() *ecdhX25519AESPublicKeyManager {
	return new(ecdhX25519AESPublicKeyManager)
}

// Primitive creates an ECDHESAESPublicKey subtle for the given serialized ECDHESAESPublicKey proto.
func (km *ecdhX25519AESPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHX25519AESPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHX25519AESPublicKey
	}

	err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidECDHX25519AESPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_aesaead_public_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeEncrypt(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhX25519AESPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhX25519AESPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhX25519AESPublicKeyManager) TypeURL() string {
	return ecdhX25519AESPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *ecdhX25519AESPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("ecdh_x25519kw_aesaead_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *ecdhX25519AESPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("ecdh_x25519kw_aesaead_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given EcdhAeadPublicKey.
func (km *ecdhX25519AESPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) error {
	err := keyset.ValidateKeyVersion(key.Version, ecdhX25519AESPublicKeyVersion)
	if err != nil {
		return fmt.Errorf("ecdh_x25519kw_aesaead_public_key_manager: invalid key: %w", err)
	}

	return validateKeyXChachaFormat(key.Params)
}
