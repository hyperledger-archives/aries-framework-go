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
	ecdhesAESPublicKeyVersion = 0
	ecdhesAESPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhesAesAeadPublicKey"
)

// common errors
var errInvalidECDHESAESPublicKey = fmt.Errorf("ecdhes_aes_public_key_manager: invalid key")

// ecdhesPublicKeyManager is an implementation of KeyManager interface.
// It generates new ECDHESPublicKey (AES) keys and produces new instances of ECDHESAEADCompositeEncrypt subtle.
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
		return nil, errInvalidECDHESAESPublicKey
	}

	ecdhesPubKey := new(ecdhespb.EcdhesAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhesPubKey)
	if err != nil {
		return nil, errInvalidECDHESAESPublicKey
	}

	_, err = km.validateKey(ecdhesPubKey)
	if err != nil {
		return nil, errInvalidECDHESAESPublicKey
	}

	var recipientsKeys []*composite.PublicKey

	for _, recKey := range ecdhesPubKey.Params.KwParams.Recipients {
		e := km.validateRecKey(recKey)
		if e != nil {
			return nil, errInvalidECDHESAESPublicKey
		}

		pub := &composite.PublicKey{
			KID:   recKey.KID,
			Type:  recKey.KeyType.String(),
			Curve: recKey.CurveType.String(),
			X:     recKey.X,
			Y:     recKey.Y,
		}

		recipientsKeys = append(recipientsKeys, pub)
	}

	rEnc, err := newRegisterECDHESAEADEncHelper(ecdhesPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, err
	}

	ptFormat := ecdhesPubKey.Params.EcPointFormat.String()

	return subtle.NewECDHESAEADCompositeEncrypt(recipientsKeys, ptFormat, rEnc, commonpb.KeyType_EC), nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhesPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhesAESPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhesPublicKeyManager) TypeURL() string {
	return ecdhesAESPublicKeyTypeURL
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
	err := keyset.ValidateKeyVersion(key.Version, ecdhesAESPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_publie_key_manager: invalid key: %s", err)
	}

	return validateKeyFormat(key.Params)
}

// validateRecKey validates the given recipient's ECDHESPublicKey.
func (km *ecdhesPublicKeyManager) validateRecKey(key *ecdhespb.EcdhesAeadRecipientPublicKey) error {
	err := keyset.ValidateKeyVersion(key.Version, ecdhesAESPublicKeyVersion)
	if err != nil {
		return fmt.Errorf("ecdhes_public_key_manager: invalid key: %s", err)
	}

	_, err = GetKeyType(key.KeyType.String())
	if err != nil {
		return err
	}

	_, err = hybrid.GetCurve(key.CurveType.String())
	if err != nil {
		return err
	}

	return nil
}
