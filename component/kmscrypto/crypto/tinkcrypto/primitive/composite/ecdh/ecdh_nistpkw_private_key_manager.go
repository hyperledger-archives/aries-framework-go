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
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

const (
	nistpECDHKWPrivateKeyVersion = 0
	nistpECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
)

// common errors.
var (
	errInvalidNISTPECDHKWPrivateKey       = errors.New("nistpkw_ecdh_private_key_manager: invalid key")
	errInvalidNISTPECDHKWPrivateKeyFormat = errors.New("nistpkw_ecdh_private_key_manager: invalid key format")
)

// nistPECDHKWPrivateKeyManager is an implementation of PrivateKeyManager interface for NIST P curved key wrapping.
// It generates new ECDHPrivateKey (NIST P KW) keys and produces new instances of ECDHAEADCompositeDecrypt subtle.
type nistPECDHKWPrivateKeyManager struct{}

// Assert that nistPECDHKWPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*nistPECDHKWPrivateKeyManager)(nil)

// newECDHNISTPAESPrivateKeyManager creates a new nistPECDHKWPrivateKeyManager.
func newECDHNISTPAESPrivateKeyManager() *nistPECDHKWPrivateKeyManager {
	return new(nistPECDHKWPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *nistPECDHKWPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidNISTPECDHKWPrivateKey
	}

	key := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKey
	}

	_, err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeDecrypt(rEnc, key.PublicKey.Params.EncParams.CEK), nil
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *nistPECDHKWPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidNISTPECDHKWPrivateKeyFormat
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKeyFormat
	}

	curve, err := validateKeyFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKeyFormat
	}

	// If CEK is present, this key is used for primitive execution only, ie this is a dummy key, not meant to be stored.
	// This avoids creating a real key to improve performance.
	if keyFormat.Params.EncParams.CEK != nil {
		return &ecdhpb.EcdhAeadPrivateKey{
			Version:  nistpECDHKWPrivateKeyVersion,
			KeyValue: []byte{},
			PublicKey: &ecdhpb.EcdhAeadPublicKey{
				Version: nistpECDHKWPrivateKeyVersion,
				Params:  keyFormat.Params,
				X:       []byte{},
				Y:       []byte{},
			},
		}, nil
	}

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  nistpECDHKWPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: nistpECDHKWPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *nistPECDHKWPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         nistpECDHKWPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *nistPECDHKWPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         nistpECDHKWPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *nistPECDHKWPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == nistpECDHKWPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *nistPECDHKWPrivateKeyManager) TypeURL() string {
	return nistpECDHKWPrivateKeyTypeURL
}

// validateKey validates the given ECDHPrivateKey and returns the KW curve.
func (km *nistPECDHKWPrivateKeyManager) validateKey(key *ecdhpb.EcdhAeadPrivateKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, nistpECDHKWPrivateKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: invalid key: %w", err)
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
			return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: invalid key: %w", err)
		}
	} else {
		c = elliptic.P384()
	}

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: GetKeyManager error: %w", err)
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: NewKeyData error: %w", err)
	}

	if params.KwParams.KeyType.String() != ecdhpb.KeyType_EC.String() {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: invalid key type %v",
			params.KwParams.KeyType)
	}

	return c, nil
}
