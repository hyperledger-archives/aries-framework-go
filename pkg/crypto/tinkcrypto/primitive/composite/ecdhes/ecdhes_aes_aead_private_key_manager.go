/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"crypto/elliptic"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
	commonpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

const (
	ecdhesAESPrivateKeyVersion = 0
	ecdhesAESPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhesAesAeadPrivateKey"
)

// common errors
var errInvalidECDHESAESPrivateKey = fmt.Errorf("ecdhes_aes_private_key_manager: invalid key")
var errInvalidECDHESAESPrivateKeyFormat = fmt.Errorf("ecdhes_aes_private_key_manager: invalid key format")

// ecdhesAESPrivateKeyManager is an implementation of PrivateKeyManager interface.
// It generates new ECDHESPrivateKey (AES) keys and produces new instances of ECDHESAEADCompositeDecrypt subtle.
type ecdhesAESPrivateKeyManager struct{}

// Assert that ecdhesAESPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdhesAESPrivateKeyManager)(nil)

// newECDHESPrivateKeyManager creates a new ecdhesAESPrivateKeyManager.
func newECDHESPrivateKeyManager() *ecdhesAESPrivateKeyManager {
	return new(ecdhesAESPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdhesAESPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHESAESPrivateKey
	}

	key := new(ecdhespb.EcdhesAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHESAESPrivateKey
	}

	curve, err := km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHESAESPrivateKey
	}

	pvt := hybrid.GetECPrivateKey(curve, key.KeyValue)

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, err
	}

	ptFormat := key.PublicKey.Params.EcPointFormat.String()

	return subtle.NewECDHESAEADCompositeDecrypt(pvt, ptFormat, rEnc, commonpb.KeyType_EC), nil
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *ecdhesAESPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDHESAESPrivateKeyFormat
	}

	keyFormat := new(ecdhespb.EcdhesAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDHESAESPrivateKeyFormat
	}

	curve, err := validateKeyFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidECDHESAESPrivateKeyFormat
	}

	keyFormat.Params.KwParams.KeyType = commonpb.KeyType_EC

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, err
	}

	return &ecdhespb.EcdhesAeadPrivateKey{
		Version:  ecdhesAESPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &ecdhespb.EcdhesAeadPublicKey{
			Version: ecdhesAESPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *ecdhesAESPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhesAESPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey
func (km *ecdhesAESPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhespb.EcdhesAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDHESAESPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDHESAESPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhesAESPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhesAESPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhesAESPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhesAESPrivateKeyManager) TypeURL() string {
	return ecdhesAESPrivateKeyTypeURL
}

// validateKey validates the given ECDHESPrivateKey and erturns the KW curve.
func (km *ecdhesAESPrivateKeyManager) validateKey(key *ecdhespb.EcdhesAeadPrivateKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhesAESPrivateKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_private_key_manager: invalid key: %s", err)
	}

	return validateKeyFormat(key.PublicKey.Params)
}

// validateKeyFormat validates the given ECDHESKeyFormat and returns the KW Curve.
func validateKeyFormat(params *ecdhespb.EcdhesAeadParams) (elliptic.Curve, error) {
	c, err := hybrid.GetCurve(params.KwParams.CurveType.String())
	if err != nil {
		return nil, err
	}

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return nil, err
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return nil, err
	}

	return c, nil
}
