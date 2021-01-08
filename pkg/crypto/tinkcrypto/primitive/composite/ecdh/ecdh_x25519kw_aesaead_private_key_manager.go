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
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

const (
	ecdhX25519AESPrivateKeyVersion = 0
	ecdhX25519AESPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhX25519KwAesAeadPrivateKey"
)

// common errors.
var (
	errInvalidECDHX25519AESPrivateKey       = errors.New("ecdh_x25519kw_aesaead_private_key_manager: invalid key")
	errInvalidECDHX25519AESPrivateKeyFormat = errors.New("ecdh_x25519kw_aesaead_private_key_manager: invalid key format") // nolint:lll
)

// ecdhX25519AESPrivateKeyManager is an implementation of PrivateKeyManager interface for X25519 key wrapping and
// AES-GCM content encryption.
// It generates new ECDHPrivateKey (X25519 KW) keys and produces new instances of ECDHAEADCompositeDecrypt subtle.
type ecdhX25519AESPrivateKeyManager struct{}

// Assert that ecdhX25519AESPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdhX25519AESPrivateKeyManager)(nil)

// newECDHX25519AESPrivateKeyManager creates a new ecdhX25519AESPrivateKeyManager.
func newECDHX25519AESPrivateKeyManager() *ecdhX25519AESPrivateKeyManager {
	return new(ecdhX25519AESPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdhX25519AESPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHX25519AESPrivateKey
	}

	key := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHX25519AESPrivateKey
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHX25519AESPrivateKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_aesaead_private_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeDecrypt(rEnc, key.PublicKey.Params.EncParams.CEK), nil
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *ecdhX25519AESPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDHX25519AESPrivateKeyFormat
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDHX25519AESPrivateKeyFormat
	}

	err = validateKeyXChachaFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidECDHX25519AESPrivateKeyFormat
	}

	pub, pvt, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_aesaead_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_aesaead_private_key_manager: Convert to X25519 pub key failed: %w", err)
	}

	x25519Pvt, err := cryptoutil.SecretEd25519toCurve25519(pvt)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_aesaead_private_key_manager: Convert to X25519 priv key failed: %w", err)
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  ecdhX25519AESPrivateKeyVersion,
		KeyValue: x25519Pvt,
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: ecdhX25519AESPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       x25519Pub,
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *ecdhX25519AESPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("ecdh_x25519kw_aesaead_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhX25519AESPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *ecdhX25519AESPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDHX25519AESPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDHX25519AESPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhX25519AESPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhX25519AESPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhX25519AESPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhX25519AESPrivateKeyManager) TypeURL() string {
	return ecdhX25519AESPrivateKeyTypeURL
}

// validateKey validates the given ECDHPrivateKey and returns the KW curve.
func (km *ecdhX25519AESPrivateKeyManager) validateKey(key *ecdhpb.EcdhAeadPrivateKey) error {
	err := keyset.ValidateKeyVersion(key.Version, ecdhX25519AESPrivateKeyVersion)
	if err != nil {
		return fmt.Errorf("ecdh_x25519kw_aesaead_private_key_manager: invalid key: %w", err)
	}

	return validateKeyXChachaFormat(key.PublicKey.Params)
}
