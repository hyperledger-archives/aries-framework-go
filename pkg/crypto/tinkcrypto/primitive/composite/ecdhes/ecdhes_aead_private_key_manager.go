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
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/hybrid"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

const (
	ecdhesPrivateKeyVersion = 0
	ecdhesPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhesAeadPrivateKey"
)

// common errors
var errInvalidECDHESPrivateKey = fmt.Errorf("ecdhes_private_key_manager: invalid key")
var errInvalidECDHESPrivateKeyFormat = fmt.Errorf("ecdhes_private_key_manager: invalid key format")

// ecdhesPrivateKeyManager is an implementation of PrivateKeyManager interface.
// It generates new ECDHESPrivateKey keys and produces new instances of ECDHESAEADCompositeDecrypt subtle.
type ecdhesPrivateKeyManager struct{}

// Assert that ecdhesPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdhesPrivateKeyManager)(nil)

// newECDHESPrivateKeyManager creates a new ecdhesPrivateKeyManager.
func newECDHESPrivateKeyManager() *ecdhesPrivateKeyManager {
	return new(ecdhesPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdhesPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHESPrivateKey
	}

	key := new(ecdhespb.EcdhesAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHESPrivateKey
	}

	curve, err := km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHESPrivateKey
	}

	pvt := hybrid.GetECPrivateKey(curve, key.KeyValue)

	rEnc, err := newRegisterECDHESAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, err
	}

	ptFormat := key.PublicKey.Params.EcPointFormat.String()

	return subtle.NewECDHESAEADCompositeDecrypt(pvt, ptFormat, rEnc)
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *ecdhesPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDHESPrivateKeyFormat
	}

	keyFormat := new(ecdhespb.EcdhesAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDHESPrivateKeyFormat
	}

	curve, err := validateKeyFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidECDHESPrivateKeyFormat
	}

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, err
	}

	return &ecdhespb.EcdhesAeadPrivateKey{
		Version:  ecdhesPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &ecdhespb.EcdhesAeadPublicKey{
			Version: ecdhesPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *ecdhesPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhesPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey
func (km *ecdhesPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhespb.EcdhesAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDHESPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDHESPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhesPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhesPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhesPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhesPrivateKeyManager) TypeURL() string {
	return ecdhesPrivateKeyTypeURL
}

// validateKey validates the given ECDHESPrivateKey and erturns the KW curve.
func (km *ecdhesPrivateKeyManager) validateKey(key *ecdhespb.EcdhesAeadPrivateKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhesPrivateKeyVersion)
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
