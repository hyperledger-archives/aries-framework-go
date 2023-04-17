/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	bbssubtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs/subtle"
	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
)

const (
	bbsSignerKeyVersion = 0
	bbsSignerKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.BBSPrivateKey"
)

// common errors.
var (
	errInvalidBBSSignerKey       = errors.New("bbs_signer_key_manager: invalid key")
	errInvalidBBSSignerKeyFormat = errors.New("bbs_signer_key_manager: invalid key format")
)

// bbsSignerKeyManager is an implementation of KeyManager interface for BBS signatures/proofs.
// It generates new BBSPrivateKeys and produces new instances of BBSSign subtle.
type bbsSignerKeyManager struct{}

// newBBSSignerKeyManager creates a new bbsSignerKeyManager.
func newBBSSignerKeyManager() *bbsSignerKeyManager {
	return new(bbsSignerKeyManager)
}

// Primitive creates an BBS Signer subtle for the given serialized BBSPrivateKey proto.
func (km *bbsSignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidBBSSignerKey
	}

	key := new(bbspb.BBSPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidBBSSignerKey.Error()+": invalid proto: %w", err)
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidBBSSignerKey.Error()+": %w", err)
	}

	return bbssubtle.NewBLS12381G2Signer(key.KeyValue), nil
}

// NewKey creates a new key according to the specification of BBSPrivateKey format.
func (km *bbsSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidBBSSignerKeyFormat
	}

	keyFormat := new(bbspb.BBSKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidBBSSignerKeyFormat.Error()+": invalid proto: %w", err)
	}

	err = validateKeyFormat(keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidBBSSignerKeyFormat.Error()+": %w", err)
	}

	var (
		pubKey  *bbs12381g2pub.PublicKey
		privKey *bbs12381g2pub.PrivateKey
	)

	// Since bbs+ in aries-framework-go only supports BLS12-381 curve on G2, we create keys of this curve and
	// group only. BBS+ keys with other curves/group field can be added later if needed.
	if keyFormat.Params.Group == bbspb.GroupField_G2 && keyFormat.Params.Curve == bbspb.BBSCurveType_BLS12_381 {
		seed := make([]byte, 32)

		_, err = rand.Read(seed)
		if err != nil {
			return nil, err
		}

		hFunc := subtle.GetHashFunc(keyFormat.Params.HashType.String())

		pubKey, privKey, err = bbs12381g2pub.GenerateKeyPair(hFunc, seed)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errInvalidBBSSignerKeyFormat
	}

	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		return nil, err
	}

	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbspb.BBSPrivateKey{
		Version:  bbsSignerKeyVersion,
		KeyValue: privKeyBytes,
		PublicKey: &bbspb.BBSPublicKey{
			Version:  bbsSignerKeyVersion,
			Params:   keyFormat.Params,
			KeyValue: pubKeyBytes,
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *bbsSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("bbs_signer_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         bbsSignerKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *bbsSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(bbspb.BBSPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidBBSSignerKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidBBSSignerKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         bbsVerifierKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *bbsSignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == bbsSignerKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *bbsSignerKeyManager) TypeURL() string {
	return bbsSignerKeyTypeURL
}

// validateKey validates the given ECDHPrivateKey and returns the KW curve.
func (km *bbsSignerKeyManager) validateKey(key *bbspb.BBSPrivateKey) error {
	err := keyset.ValidateKeyVersion(key.Version, bbsSignerKeyVersion)
	if err != nil {
		return fmt.Errorf("bbs_signer_key_manager: invalid key: %w", err)
	}

	return validateKeyParams(key.PublicKey.Params)
}

// validateKeyFormat validates the given BBS curve and Group field.
func validateKeyFormat(format *bbspb.BBSKeyFormat) error {
	return validateKeyParams(format.Params)
}

func validateKeyParams(params *bbspb.BBSParams) error {
	switch params.Curve {
	case bbspb.BBSCurveType_BLS12_381:
	default:
		return fmt.Errorf("bad curve '%s'", params.Curve)
	}

	switch params.Group {
	case bbspb.GroupField_G1, bbspb.GroupField_G2:
	default:
		return fmt.Errorf("bad group field '%s'", params.Group)
	}

	switch params.HashType {
	case commonpb.HashType_SHA256, commonpb.HashType_SHA384, commonpb.HashType_SHA512:
	default:
		return fmt.Errorf("unsupported hash type '%s'", params.HashType)
	}

	return nil
}
