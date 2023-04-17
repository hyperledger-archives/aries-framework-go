/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1

import (
	"fmt"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
)

const (
	secp256k1VerifierKeyVersion = 0
	secp256k1VerifierTypeURL    = "type.googleapis.com/google.crypto.tink.secp256k1PublicKey"
)

// common errors.
var (
	errInvalidsecp256k1VerifierKey     = fmt.Errorf("secp256k1_verifier_key_manager: invalid key")
	errsecp256k1VerifierNotImplemented = fmt.Errorf("secp256k1_verifier_key_manager: not implemented")
)

// secp256k1VerifierKeyManager is an implementation of KeyManager interface.
// It doesn't support key generation.
type secp256k1VerifierKeyManager struct{}

// newSecp256K1VerifierKeyManager creates a new secp256k1VerifierKeyManager.
func newSecp256K1VerifierKeyManager() *secp256k1VerifierKeyManager {
	return new(secp256k1VerifierKeyManager)
}

// Primitive creates an secp256k1Verifier subtle for the given serialized secp256k1PublicKey proto.
func (km *secp256k1VerifierKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidsecp256k1VerifierKey
	}

	key := new(secp256k1pb.Secp256K1PublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidsecp256k1VerifierKey
	}

	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("secp256k1_verifier_key_manager: %w", err)
	}

	hash, curve, encoding := getSecp256K1ParamNames(key.Params)

	ret, err := subtle.NewSecp256K1Verifier(hash, curve, encoding, key.X, key.Y)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_verifier_key_manager: invalid key: %w", err)
	}

	return ret, nil
}

// NewKey is not implemented.
func (km *secp256k1VerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errsecp256k1VerifierNotImplemented
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized secp256k1KeyFormat. It should be used solely by the key management API.
func (km *secp256k1VerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errsecp256k1VerifierNotImplemented
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *secp256k1VerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == secp256k1VerifierTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *secp256k1VerifierKeyManager) TypeURL() string {
	return secp256k1VerifierTypeURL
}

// validateKey validates the given secp256k1PublicKey.
func (km *secp256k1VerifierKeyManager) validateKey(key *secp256k1pb.Secp256K1PublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, secp256k1VerifierKeyVersion); err != nil {
		return fmt.Errorf("secp256k1_verifier_key_manager: %w", err)
	}

	hash, curve, encoding := getSecp256K1ParamNames(key.Params)

	return ValidateSecp256K1Params(hash, curve, encoding)
}
