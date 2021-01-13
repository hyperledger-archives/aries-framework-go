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
	ecdhNISTPAESPrivateKeyVersion = 0
	ecdhNISTPAESPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhNistPKwAesAeadPrivateKey"
)

// common errors.
var (
	errInvalidECDHNISTPAESPrivateKey       = errors.New("ecdh_nistpkw_aesaead_private_key_manager: invalid key")
	errInvalidECDHNISTPAESPrivateKeyFormat = errors.New("ecdh_nistpkw_aesaead_private_key_manager: invalid key format") // nolint:lll
)

// ecdhNISTPAESPrivateKeyManager is an implementation of PrivateKeyManager interface for NIST P curved key wrapping and
// AES-GCM content encryption.
// It generates new ECDHPrivateKey (NIST P KW) keys and produces new instances of ECDHAEADCompositeDecrypt subtle.
type ecdhNISTPAESPrivateKeyManager struct{}

// Assert that ecdhNISTPAESPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdhNISTPAESPrivateKeyManager)(nil)

// newECDHNISTPAESPrivateKeyManager creates a new ecdhNISTPAESPrivateKeyManager.
func newECDHNISTPAESPrivateKeyManager() *ecdhNISTPAESPrivateKeyManager {
	return new(ecdhNISTPAESPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdhNISTPAESPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHNISTPAESPrivateKey
	}

	key := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHNISTPAESPrivateKey
	}

	_, err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHNISTPAESPrivateKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_private_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeDecrypt(rEnc, key.PublicKey.Params.EncParams.CEK), nil
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *ecdhNISTPAESPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDHNISTPAESPrivateKeyFormat
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDHNISTPAESPrivateKeyFormat
	}

	curve, err := validateKeyFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidECDHNISTPAESPrivateKeyFormat
	}

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  ecdhNISTPAESPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: ecdhNISTPAESPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *ecdhNISTPAESPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhNISTPAESPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *ecdhNISTPAESPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDHNISTPAESPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDHNISTPAESPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhNISTPAESPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhNISTPAESPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhNISTPAESPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhNISTPAESPrivateKeyManager) TypeURL() string {
	return ecdhNISTPAESPrivateKeyTypeURL
}

// validateKey validates the given ECDHPrivateKey and returns the KW curve.
func (km *ecdhNISTPAESPrivateKeyManager) validateKey(key *ecdhpb.EcdhAeadPrivateKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhNISTPAESPrivateKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_private_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.PublicKey.Params)
}

// validateKeyFormat validates the given ECDHESKeyFormat and returns the KW Curve.
func validateKeyFormat(params *ecdhpb.EcdhAeadParams) (elliptic.Curve, error) {
	var (
		c   elliptic.Curve
		err error
	)

	// if CEK is set, then curve is unknown, ie this is not a recipient key, it's a primitive execution key for
	// Encryption/Decryption. Set P-384 curve for key generation
	if params.EncParams.CEK == nil {
		c, err = hybrid.GetCurve(params.KwParams.CurveType.String())
		if err != nil {
			return nil, fmt.Errorf("ecdh_nistpkw_aesaead_private_key_manager: invalid key: %w", err)
		}
	} else {
		c = elliptic.P384()
	}

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_private_key_manager: GetKeyManager error: %w", err)
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_private_key_manager: NewKeyData error: %w", err)
	}

	if params.KwParams.KeyType.String() != ecdhpb.KeyType_EC.String() {
		return nil, fmt.Errorf("ecdh_nistpkw_aesaead_private_key_manager: invalid key type %v",
			params.KwParams.KeyType)
	}

	return c, nil
}
