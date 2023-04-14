/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs/subtle"
	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
)

const (
	bbsVerifierKeyVersion = 0
	bbsVerifierKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.BBSPublicKey"
)

// common errors.
var errInvalidBBSVerifierKey = errors.New("bbs_verifier_key_manager: invalid key")

// bbsVerifierKeyManager is an implementation of KeyManager interface for BBS signature/proof verification.
// It doesn't support key generation.
type bbsVerifierKeyManager struct{}

// newBBSVerifierKeyManager creates a new bbsVerifierKeyManager.
func newBBSVerifierKeyManager() *bbsVerifierKeyManager {
	return new(bbsVerifierKeyManager)
}

// Primitive creates an BBS Verifier subtle for the given serialized BBSPublicKey proto.
func (km *bbsVerifierKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidBBSVerifierKey
	}

	bbsPubKey := new(bbspb.BBSPublicKey)

	err := proto.Unmarshal(serializedKey, bbsPubKey)
	if err != nil {
		return nil, errInvalidBBSVerifierKey
	}

	err = km.validateKey(bbsPubKey)
	if err != nil {
		return nil, errInvalidBBSVerifierKey
	}

	return subtle.NewBLS12381G2Verifier(bbsPubKey.KeyValue), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *bbsVerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == bbsVerifierKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *bbsVerifierKeyManager) TypeURL() string {
	return bbsVerifierKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *bbsVerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("bbs_verifier_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *bbsVerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("bbs_verifier_key_manager: NewKeyData not implemented")
}

// validateKey validates the given EcdhAeadPublicKey.
func (km *bbsVerifierKeyManager) validateKey(key *bbspb.BBSPublicKey) error {
	err := keyset.ValidateKeyVersion(key.Version, bbsVerifierKeyVersion)
	if err != nil {
		return fmt.Errorf("bbs_verifier_key_manager: invalid key: %w", err)
	}

	return validateKeyParams(key.Params)
}
