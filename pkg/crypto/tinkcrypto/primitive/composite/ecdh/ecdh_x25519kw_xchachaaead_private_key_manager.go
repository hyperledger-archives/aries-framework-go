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

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

const (
	ecdhX25519XChachaPrivateKeyVersion = 0
	ecdhX25519XChachaPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhX25519KwXChachaAeadPrivateKey" // nolint:lll
)

// common errors.
var (
	errInvalidECDHX25519XChachaPrivateKey       = errors.New("ecdh_x25519kw_xchachaaead_private_key_manager: invalid key")        // nolint:lll
	errInvalidECDHX25519XChachaPrivateKeyFormat = errors.New("ecdh_x25519kw_xchachaaead_private_key_manager: invalid key format") // nolint:lll
)

// ecdhX25519XChachaPrivateKeyManager is an implementation of PrivateKeyManager interface for X25519 key wrapping and
// XChacha20Poly1305 content encryption.
// It generates new ECDHPrivateKey (X25519 KW) keys and produces new instances of ECDHAEADCompositeDecrypt subtle.
type ecdhX25519XChachaPrivateKeyManager struct{}

// Assert that ecdhX25519XChachaPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdhX25519XChachaPrivateKeyManager)(nil)

// newECDHX25519XChachaPrivateKeyManager creates a new ecdhX25519XChachaPrivateKeyManager.
func newECDHX25519XChachaPrivateKeyManager() *ecdhX25519XChachaPrivateKeyManager {
	return new(ecdhX25519XChachaPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdhX25519XChachaPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHX25519XChachaPrivateKey
	}

	key := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHX25519XChachaPrivateKey
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHX25519XChachaPrivateKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeDecrypt(rEnc, key.PublicKey.Params.EncParams.CEK), nil
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *ecdhX25519XChachaPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDHX25519XChachaPrivateKeyFormat
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDHX25519XChachaPrivateKeyFormat
	}

	err = validateKeyXChachaFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidECDHX25519XChachaPrivateKeyFormat
	}

	pub, pvt, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: Convert to X25519 pub key failed: %w", err)
	}

	x25519Pvt, err := cryptoutil.SecretEd25519toCurve25519(pvt)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: Convert to X25519 priv key failed: %w", err)
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  ecdhX25519XChachaPrivateKeyVersion,
		KeyValue: x25519Pvt,
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: ecdhX25519XChachaPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       x25519Pub,
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *ecdhX25519XChachaPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhX25519XChachaPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *ecdhX25519XChachaPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDHX25519XChachaPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDHX25519XChachaPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhX25519XChachaPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhX25519XChachaPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhX25519XChachaPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhX25519XChachaPrivateKeyManager) TypeURL() string {
	return ecdhX25519XChachaPrivateKeyTypeURL
}

// validateKey validates the given ECDHPrivateKey and returns the KW curve.
func (km *ecdhX25519XChachaPrivateKeyManager) validateKey(key *ecdhpb.EcdhAeadPrivateKey) error {
	err := keyset.ValidateKeyVersion(key.Version, ecdhX25519XChachaPrivateKeyVersion)
	if err != nil {
		return fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: invalid key: %w", err)
	}

	return validateKeyXChachaFormat(key.PublicKey.Params)
}

// validateKeyXChachaFormat validates the given ECDHESKeyFormat and returns the KW Curve.
func validateKeyXChachaFormat(params *ecdhpb.EcdhAeadParams) error {
	var err error

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: GetKeyManager error: %w", err)
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: NewKeyData error: %w", err)
	}

	if params.KwParams.KeyType.String() != ecdhpb.KeyType_OKP.String() {
		return fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: invalid key type %v",
			params.KwParams.KeyType)
	}

	// if CEK is not set, this is a KW key for storage, it must have the curve.
	// if it is set, then this is a primitive execution key, the curve is not needed since we do content encryption.
	if params.EncParams.CEK == nil &&
		params.KwParams.CurveType.String() != commonpb.EllipticCurveType_CURVE25519.String() {
		return fmt.Errorf("ecdh_x25519kw_xchachaaead_private_key_manager: invalid curve %v",
			params.KwParams.CurveType)
	}

	return nil
}
