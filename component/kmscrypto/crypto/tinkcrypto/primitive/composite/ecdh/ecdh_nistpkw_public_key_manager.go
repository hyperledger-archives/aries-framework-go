/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"crypto/elliptic"
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
	nistpECDHKWPublicKeyVersion = 0
	nistpECDHKWPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey"
)

// common errors.
var errInvalidNISTPECDHKWPublicKey = errors.New("nistpkw_ecdh_public_key_manager: invalid key")

// nistPECDHKWPublicKeyManager is an implementation of KeyManager interface for NIST P curved key wrapping.
// It generates new ECDHPublicKey (AES) keys and produces new instances of ECDHAEADCompositeEncrypt subtle.
type nistPECDHKWPublicKeyManager struct{}

// Assert that nistPECDHKWPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*nistPECDHKWPublicKeyManager)(nil)

// newECDHNISTPAESPublicKeyManager creates a new nistPECDHKWPublicKeyManager.
func newECDHNISTPAESPublicKeyManager() *nistPECDHKWPublicKeyManager {
	return new(nistPECDHKWPublicKeyManager)
}

// Primitive creates an ECDHESPublicKey subtle for the given serialized ECDHESPublicKey proto.
func (km *nistPECDHKWPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidNISTPECDHKWPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPublicKey
	}

	_, err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_public_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeEncrypt(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *nistPECDHKWPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == nistpECDHKWPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *nistPECDHKWPublicKeyManager) TypeURL() string {
	return nistpECDHKWPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *nistPECDHKWPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("nistpkw_ecdh_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *nistPECDHKWPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("nistpkw_ecdh_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given EcdhAeadPublicKey.
func (km *nistPECDHKWPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, nistpECDHKWPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_public_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.Params)
}
