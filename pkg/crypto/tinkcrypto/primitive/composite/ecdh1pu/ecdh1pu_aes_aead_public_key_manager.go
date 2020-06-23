/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh1pu

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
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu/subtle"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdh1pupb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh1pu_aead_go_proto"
)

const (
	ecdh1puAESPublicKeyVersion = 0
	ecdh1puAESPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.Ecdh1puAesAeadPublicKey"
)

// common errors
var errInvalidECDH1PUAESPublicKey = errors.New("ecdh1pu_aes_public_key_manager: invalid key")

// ecdh1puPublicKeyManager is an implementation of KeyManager interface.
// It generates new ECDH1PUPublicKey (AES) keys and produces new instances of ECDH1PUAEADCompositeEncrypt subtle.
type ecdh1puPublicKeyManager struct{}

// Assert that ecdh1puPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*ecdh1puPublicKeyManager)(nil)

// newECDH1PUPublicKeyManager creates a new ecdh1puPublicKeyManager.
func newECDH1PUPublicKeyManager() *ecdh1puPublicKeyManager {
	return new(ecdh1puPublicKeyManager)
}

// Primitive creates an ECDH1PUPublicKey subtle for the given serialized ECDH1PUPublicKey proto.
func (km *ecdh1puPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDH1PUAESPublicKey
	}

	ecdh1puPubKey := new(ecdh1pupb.Ecdh1PuAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdh1puPubKey)
	if err != nil {
		return nil, errInvalidECDH1PUAESPublicKey
	}

	senderPrivKey, err := buildPrivKeyFromProto(ecdh1puPubKey)
	if err != nil {
		return nil, errInvalidECDH1PUAESPublicKey
	}

	_, err = km.validateKey(ecdh1puPubKey)
	if err != nil {
		return nil, errInvalidECDH1PUAESPublicKey
	}

	var recipientsKeys []*composite.PublicKey

	for _, recKey := range ecdh1puPubKey.Params.KwParams.Recipients {
		e := km.validateRecKey(recKey)
		if e != nil {
			return nil, errInvalidECDH1PUAESPublicKey
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

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdh1puPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_public_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	ptFormat := ecdh1puPubKey.Params.EcPointFormat.String()

	return subtle.NewECDH1PUAEADCompositeEncrypt(recipientsKeys, senderPrivKey, ptFormat, rEnc, compositepb.KeyType_EC),
		nil
}

func buildPrivKeyFromProto(key *ecdh1pupb.Ecdh1PuAeadPublicKey) (*hybrid.ECPrivateKey, error) {
	c, err := hybrid.GetCurve(key.Params.KwParams.CurveType.String())
	if err != nil {
		return nil, err
	}

	pk := hybrid.GetECPrivateKey(c, key.KWD)
	pv := &hybrid.ECPrivateKey{
		PublicKey: hybrid.ECPublicKey{
			Curve: c,
			Point: hybrid.ECPoint{
				X: pk.PublicKey.Point.X,
				Y: pk.PublicKey.Point.Y,
			},
		},
		D: pk.D,
	}

	return pv, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdh1puPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdh1puAESPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdh1puPublicKeyManager) TypeURL() string {
	return ecdh1puAESPublicKeyTypeURL
}

// NewKey is not implemented for public key manager.
func (km *ecdh1puPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("ecdh1pu_aes_public_key_manager: NewKey not implemented")
}

// NewKeyData is not implemented for public key manager.
func (km *ecdh1puPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("ecdh1pu_aes_public_key_manager: NewKeyData not implemented")
}

// validateKey validates the given ECDHESPublicKey.
func (km *ecdh1puPublicKeyManager) validateKey(key *ecdh1pupb.Ecdh1PuAeadPublicKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdh1puAESPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdh1pu_aes_publie_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.Params)
}

// validateRecKey validates the given recipient's ECDHESPublicKey.
func (km *ecdh1puPublicKeyManager) validateRecKey(key *compositepb.ECPublicKey) error {
	err := keyset.ValidateKeyVersion(key.Version, ecdh1puAESPublicKeyVersion)
	if err != nil {
		return fmt.Errorf("ecdh1pu_aes_public_key_manager: invalid key: %w", err)
	}

	_, err = composite.GetKeyType(key.KeyType.String())
	if err != nil {
		return fmt.Errorf("ecdh1pu_aes_public_key_manager: GetKeyType error: %w", err)
	}

	_, err = hybrid.GetCurve(key.CurveType.String())
	if err != nil {
		return fmt.Errorf("ecdh1pu_aes_public_key_manager: GetCurve error: %w", err)
	}

	return nil
}
