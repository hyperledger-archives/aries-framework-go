/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh1pu

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu/subtle"
	commonpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdh1pupb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh1pu_aead_go_proto"
)

const (
	ecdh1puAESPrivateKeyVersion = 0
	ecdh1puAESPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.Ecdh1puAesAeadPrivateKey"
)

// common errors.
var (
	errInvalidECDH1PUAESPrivateKey       = errors.New("ecdh1pu_aes_private_key_manager: invalid key")
	errInvalidECDH1PUAESPrivateKeyFormat = errors.New("ecdh1pu_aes_private_key_manager: invalid key format")
)

// ecdh1puAESPrivateKeyManager is an implementation of PrivateKeyManager interface.
// It generates new ECDHESPrivateKey (AES) keys and produces new instances of ECDH1PUAEADCompositeDecrypt subtle.
type ecdh1puAESPrivateKeyManager struct{}

// Assert that ecdh1puAESPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdh1puAESPrivateKeyManager)(nil)

// newECDH1PUPrivateKeyManager creates a new ecdh1puAESPrivateKeyManager.
func newECDH1PUPrivateKeyManager() *ecdh1puAESPrivateKeyManager {
	return new(ecdh1puAESPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdh1puAESPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDH1PUAESPrivateKey
	}

	key := new(ecdh1pupb.Ecdh1PuAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDH1PUAESPrivateKey
	}

	curve, err := km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDH1PUAESPrivateKey
	}

	recPvtKey := hybrid.GetECPrivateKey(curve, key.KeyValue)

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_private_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	ptFormat := key.PublicKey.Params.EcPointFormat.String()

	if key.PublicKey.Params.KwParams.Sender == nil {
		return nil, errors.New("ecdh1pu_aes_private_key_manager: sender public key is required for primitive " +
			"execution")
	}

	crv, err := hybrid.GetCurve(key.PublicKey.Params.KwParams.Sender.CurveType.String())
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_private_key_manager: GetCurve failed: %w", err)
	}

	senderPubKey := &hybrid.ECPublicKey{
		Curve: crv,
		Point: hybrid.ECPoint{
			X: new(big.Int).SetBytes(key.PublicKey.Params.KwParams.Sender.X),
			Y: new(big.Int).SetBytes(key.PublicKey.Params.KwParams.Sender.Y),
		},
	}

	return subtle.NewECDH1PUAEADCompositeDecrypt(senderPubKey, recPvtKey, ptFormat, rEnc, commonpb.KeyType_EC), nil
}

// NewKey creates a new key according to the specification of ECDH1PUPrivateKey format.
func (km *ecdh1puAESPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDH1PUAESPrivateKeyFormat
	}

	keyFormat := new(ecdh1pupb.Ecdh1PuAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDH1PUAESPrivateKeyFormat
	}

	curve, err := validateKeyFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidECDH1PUAESPrivateKeyFormat
	}

	keyFormat.Params.KwParams.KeyType = commonpb.KeyType_EC

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	return &ecdh1pupb.Ecdh1PuAeadPrivateKey{
		Version:  ecdh1puAESPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &ecdh1pupb.Ecdh1PuAeadPublicKey{
			Version: ecdh1puAESPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *ecdh1puAESPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdh1puAESPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *ecdh1puAESPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdh1pupb.Ecdh1PuAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDH1PUAESPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDH1PUAESPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdh1puAESPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdh1puAESPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdh1puAESPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdh1puAESPrivateKeyManager) TypeURL() string {
	return ecdh1puAESPrivateKeyTypeURL
}

// validateKey validates the given ECDH1PUPrivateKey and returns the KW curve.
func (km *ecdh1puAESPrivateKeyManager) validateKey(key *ecdh1pupb.Ecdh1PuAeadPrivateKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdh1puAESPrivateKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_private_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.PublicKey.Params)
}

// validateKeyFormat validates the given ECDHESKeyFormat and returns the KW Curve.
func validateKeyFormat(params *ecdh1pupb.Ecdh1PuAeadParams) (elliptic.Curve, error) {
	c, err := hybrid.GetCurve(params.KwParams.CurveType.String())
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_private_key_manager: invalid key: %w", err)
	}

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_private_key_manager: GetKeyManager error: %w", err)
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_private_key_manager: GetCurve error: %w", err)
	}

	return c, nil
}
