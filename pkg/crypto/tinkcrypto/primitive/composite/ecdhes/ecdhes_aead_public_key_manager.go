/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/hybrid"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

const (
	ecdhesPublicKeyVersion = 0
	ecdhesPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhesAeadPublicKey"
)

// common errors
var errInvalidECDHESPublicKey = fmt.Errorf("ecdhes_public_key_manager: invalid key")

// ecdhesPublicKeyManager is an implementation of KeyManager interface.
// It generates new ECDHESPublicKey keys and produces new instances of ECDHESAEADCompositeEncrypt subtle.
type ecdhesPublicKeyManager struct{}

// Assert that ecdhesPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*ecdhesPublicKeyManager)(nil)

// newECDHESPublicKeyManager creates a new ecdhesPublicKeyManager.
func newECDHESPublicKeyManager() *ecdhesPublicKeyManager {
	return new(ecdhesPublicKeyManager)
}

// Primitive creates an ECDHESPublicKey subtle for the given serialized ECDHESPublicKey proto.
func (km *ecdhesPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHESPublicKey
	}

	ecdhesPubKey := new(ecdhespb.EcdhesAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhesPubKey)
	if err != nil {
		return nil, errInvalidECDHESPublicKey
	}

	_, err = km.validateKey(ecdhesPubKey)
	if err != nil {
		return nil, errInvalidECDHESPublicKey
	}

	var recipientsKeys []*hybrid.ECPublicKey

	for _, recKey := range ecdhesPubKey.Params.KwParams.Recipients {
		recCurve, e := km.validateRecKey(recKey)
		if e != nil {
			return nil, errInvalidECDHESPublicKey
		}

		pub := &hybrid.ECPublicKey{
			Curve: recCurve,
			Point: hybrid.ECPoint{
				X: new(big.Int).SetBytes(recKey.X),
				Y: new(big.Int).SetBytes(recKey.Y),
			},
		}

		recipientsKeys = append(recipientsKeys, pub)
	}

	rEnc, err := newRegisterECDHESAEADEncHelper(ecdhesPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, err
	}

	ptFormat := ecdhesPubKey.Params.EcPointFormat.String()

	return subtle.NewECDHESAEADCompositeEncrypt(recipientsKeys, ptFormat, rEnc)
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhesPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhesPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhesPublicKeyManager) TypeURL() string {
	return ecdhesPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *ecdhesPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, fmt.Errorf("ecdhes_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *ecdhesPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("ecdhes_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given ECDHESPublicKey.
func (km *ecdhesPublicKeyManager) validateKey(key *ecdhespb.EcdhesAeadPublicKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhesPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_publie_key_manager: invalid key: %s", err)
	}

	return validateKeyFormat(key.Params)
}

// validateRecKey validates the given recipient's ECDHESPublicKey.
func (km *ecdhesPublicKeyManager) validateRecKey(key *ecdhespb.EcdhesAeadRecipientPublicKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhesPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_public_key_manager: invalid key: %s", err)
	}

	c, err := hybrid.GetCurve(key.CurveType.String())
	if err != nil {
		return nil, err
	}

	return c, nil
}
