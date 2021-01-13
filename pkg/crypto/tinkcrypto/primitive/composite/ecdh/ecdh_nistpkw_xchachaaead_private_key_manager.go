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
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

const (
	ecdhNISTPXChachaPrivateKeyVersion = 0
	ecdhNISTPXChachaPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhNistPKwXChachaAeadPrivateKey" // nolint:lll
)

// common errors.
var (
	errInvalidECDHNISTPXChachaPrivateKey       = errors.New("ecdh_nistpkw_xchachaaead_private_key_manager: invalid key")        // nolint:lll
	errInvalidECDHNISTPXChachaPrivateKeyFormat = errors.New("ecdh_nistpkw_xchachaaead_private_key_manager: invalid key format") // nolint:lll
)

// ecdhNISTPXChachaPrivateKeyManager is an implementation of PrivateKeyManager interface for NIST P curved key wrapping
// and XChacha20Poly1305 content encryption.
// It generates new ECDHPrivateKey (NIST P KW) keys and produces new instances of ECDHAEADCompositeDecrypt subtle.
type ecdhNISTPXChachaPrivateKeyManager struct{}

// Assert that ecdhNISTPXChachaPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdhNISTPXChachaPrivateKeyManager)(nil)

// newECDHNISTPXChachaPrivateKeyManager creates a new ecdhNISTPXChachaPrivateKeyManager.
func newECDHNISTPXChachaPrivateKeyManager() *ecdhNISTPXChachaPrivateKeyManager {
	return new(ecdhNISTPXChachaPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdhNISTPXChachaPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHNISTPXChachaPrivateKey
	}

	key := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHNISTPXChachaPrivateKey
	}

	_, err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHNISTPXChachaPrivateKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_xchachaaead_private_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeDecrypt(rEnc, key.PublicKey.Params.EncParams.CEK), nil
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *ecdhNISTPXChachaPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDHNISTPXChachaPrivateKeyFormat
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDHNISTPXChachaPrivateKeyFormat
	}

	curve, err := validateKeyFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidECDHNISTPXChachaPrivateKeyFormat
	}

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_xchachaaead_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  ecdhNISTPXChachaPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: ecdhNISTPXChachaPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *ecdhNISTPXChachaPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_xchachaaead_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhNISTPXChachaPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *ecdhNISTPXChachaPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDHNISTPXChachaPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDHNISTPXChachaPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhNISTPXChachaPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhNISTPXChachaPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhNISTPXChachaPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhNISTPXChachaPrivateKeyManager) TypeURL() string {
	return ecdhNISTPXChachaPrivateKeyTypeURL
}

// validateKey validates the given ECDHPrivateKey and returns the KW curve.
func (km *ecdhNISTPXChachaPrivateKeyManager) validateKey(key *ecdhpb.EcdhAeadPrivateKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhNISTPXChachaPrivateKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_xchachaaead_private_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.PublicKey.Params)
}
