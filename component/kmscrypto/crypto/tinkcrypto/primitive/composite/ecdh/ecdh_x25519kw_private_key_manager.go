/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

const (
	x25519ECDHKWPrivateKeyVersion = 0
	x25519ECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey"
)

// common errors.
var (
	errInvalidx25519ECDHKWPrivateKey       = errors.New("x25519kw_ecdh_private_key_manager: invalid key")
	errInvalidx25519ECDHKWPrivateKeyFormat = errors.New("x25519kw_ecdh_private_key_manager: invalid key format")
)

// x25519ECDHKWPrivateKeyManager is an implementation of PrivateKeyManager interface for X25519 key wrapping.
// It generates new ECDHPrivateKey (X25519 KW) keys and produces new instances of ECDHAEADCompositeDecrypt subtle.
type x25519ECDHKWPrivateKeyManager struct{}

// Assert that x25519ECDHKWPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*x25519ECDHKWPrivateKeyManager)(nil)

// newX25519ECDHKWPrivateKeyManager creates a new x25519ECDHKWPrivateKeyManager.
func newX25519ECDHKWPrivateKeyManager() *x25519ECDHKWPrivateKeyManager {
	return new(x25519ECDHKWPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *x25519ECDHKWPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidx25519ECDHKWPrivateKey
	}

	key := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPrivateKey
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPrivateKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeDecrypt(rEnc, key.PublicKey.Params.EncParams.CEK), nil
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *x25519ECDHKWPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidx25519ECDHKWPrivateKeyFormat
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPrivateKeyFormat
	}

	err = validateKeyXChachaFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPrivateKeyFormat
	}

	// If CEK is present, this key is used for primitive execution only, ie this is a dummy key, not meant to be stored.
	// This avoids creating a real key to improve performance.
	if keyFormat.Params.EncParams.CEK != nil {
		return &ecdhpb.EcdhAeadPrivateKey{
			Version:  x25519ECDHKWPrivateKeyVersion,
			KeyValue: []byte{},
			PublicKey: &ecdhpb.EcdhAeadPublicKey{
				Version: x25519ECDHKWPrivateKeyVersion,
				Params:  keyFormat.Params,
				X:       []byte{},
			},
		}, nil
	}

	pub, pvt, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: Convert to X25519 pub key failed: %w", err)
	}

	x25519Pvt, err := cryptoutil.SecretEd25519toCurve25519(pvt)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: Convert to X25519 priv key failed: %w", err)
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  x25519ECDHKWPrivateKeyVersion,
		KeyValue: x25519Pvt,
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: x25519ECDHKWPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       x25519Pub,
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *x25519ECDHKWPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         x25519ECDHKWPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *x25519ECDHKWPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         x25519ECDHKWPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *x25519ECDHKWPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == x25519ECDHKWPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *x25519ECDHKWPrivateKeyManager) TypeURL() string {
	return x25519ECDHKWPrivateKeyTypeURL
}

// validateKey validates the given ECDHPrivateKey and returns the KW curve.
func (km *x25519ECDHKWPrivateKeyManager) validateKey(key *ecdhpb.EcdhAeadPrivateKey) error {
	err := keyset.ValidateKeyVersion(key.Version, x25519ECDHKWPrivateKeyVersion)
	if err != nil {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: invalid key: %w", err)
	}

	return validateKeyXChachaFormat(key.PublicKey.Params)
}

// validateKeyXChachaFormat validates the given ECDHESKeyFormat and returns the KW Curve.
func validateKeyXChachaFormat(params *ecdhpb.EcdhAeadParams) error {
	var err error

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: GetKeyManager error: %w", err)
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: NewKeyData error: %w", err)
	}

	if params.KwParams.KeyType.String() != ecdhpb.KeyType_OKP.String() {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: invalid key type %v",
			params.KwParams.KeyType)
	}

	// if CEK is not set, this is a KW key for storage, it must have the curve.
	// if it is set, then this is a primitive execution key, the curve is not needed since we do content encryption.
	if params.EncParams.CEK == nil &&
		params.KwParams.CurveType.String() != commonpb.EllipticCurveType_CURVE25519.String() {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: invalid curve %v",
			params.KwParams.CurveType)
	}

	return nil
}
