//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	clsubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/subtle"
	clpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/cl_go_proto"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

const (
	clIssuerKeyVersion = 0
	clIssuerKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.CLIssuerKey"
)

// common errors.
var (
	errInvalidCLIssuerKey       = errors.New("cl_issuer_key_manager: invalid cred def key")
	errInvalidCLIssuerKeyFormat = errors.New("cl_issuer_key_manager: invalid cred def key format")
	errInvalidKeyUrsa           = errors.New("cl_issuer_key_manager: can not create Ursa cred def key")
)

// clIssuerKeyManager is an implementation of KeyManager interface for CL signatures/proofs.
// It generates new CredDefPrivateKeys and produces new instances of CLIssuer subtle.
type clIssuerKeyManager struct{}

// Сreates a new clIssuerKeyManager.
func newCLIssuerKeyManager() *clIssuerKeyManager {
	return new(clIssuerKeyManager)
}

// Primitive creates a CL Issuer subtle for the given serialized CredDefPrivateKey proto.
func (km *clIssuerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidCLIssuerKey
	}

	key := new(clpb.CLCredDefPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLIssuerKey.Error()+": invalid proto: %w", err)
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLIssuerKey.Error()+": %w", err)
	}

	clIssuer, err := clsubtle.NewCLIssuer(key.KeyValue, key.PublicKey.KeyValue, key.PublicKey.KeyCorrectnessProof, key.PublicKey.Params.Attrs)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLIssuerKey.Error()+": invalid ursa key: %w", err)
	}

	return clIssuer, nil
}

// NewKey creates a new key according to the specification of CLCredDefPrivateKey format.
func (km *clIssuerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidCLIssuerKeyFormat
	}

	// 1. Unmarshal to KeyFormat
	keyFormat := new(clpb.CLCredDefKeyFormat)
	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLIssuerKeyFormat.Error()+": invalid proto: %w", err)
	}
	err = validateKeyFormat(keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLIssuerKeyFormat.Error()+": %w", err)
	}

	// 2. Create Credentials Schema
	schema, nonSchema, err := clsubtle.BuildSchema(keyFormat.Params.Attrs)
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": %w", err)
	}

	// 4. Create CredDef
	credDef, err := ursa.NewCredentialDef(schema, nonSchema, false)
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": %w", err)
	}

	// 5. serialize keys to JSONs
	pubKeyBytes, err := credDef.PubKey.ToJSON()
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": can not convert cred def pub key to JSON: %w", err)
	}
	privKeyBytes, err := credDef.PrivKey.ToJSON()
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": can not convert cred def priv key to JSON: %w", err)
	}
	correctnessProofBytes, err := credDef.KeyCorrectnessProof.ToJSON()
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": can not convert cred def correctness proof to JSON: %w", err)
	}

	return &clpb.CLCredDefPrivateKey{
		Version:  clIssuerKeyVersion,
		KeyValue: privKeyBytes,
		PublicKey: &clpb.CLCredDefPublicKey{
			Version:             clIssuerKeyVersion,
			Params:              keyFormat.Params,
			KeyValue:            pubKeyBytes,
			KeyCorrectnessProof: correctnessProofBytes,
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of CLCredDefPrivateKey Format.
// It should be used solely by the key management API.
func (km *clIssuerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLIssuerKeyFormat.Error()+": invalid proto: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         clIssuerKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *clIssuerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(clpb.CLCredDefPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLIssuerKey.Error()+": invalid proto: %w", err)
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLIssuerKey.Error()+": invalid proto: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         clIssuerKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *clIssuerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == clIssuerKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *clIssuerKeyManager) TypeURL() string {
	return clIssuerKeyTypeURL
}

// validateKey validates the given CLCredDefPrivateKey
func (km *clIssuerKeyManager) validateKey(key *clpb.CLCredDefPrivateKey) error {
	err := keyset.ValidateKeyVersion(key.Version, clIssuerKeyVersion)
	if err != nil {
		return fmt.Errorf("invalid key version: %w", err)
	}
	return validateKeyParams(key.PublicKey.Params)
}

func validateKeyFormat(format *clpb.CLCredDefKeyFormat) error {
	return validateKeyParams(format.Params)
}

func validateKeyParams(params *clpb.CLCredDefParams) error {
	if len(params.Attrs) == 0 {
		return fmt.Errorf("empty attributes")
	}
	return nil
}
