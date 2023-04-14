//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
	"google.golang.org/protobuf/proto"

	clsubtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/subtle"
	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/internal/ursautil"
)

const (
	clSignerKeyVersion = 0
	clSignerKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.CLCredDefKey"
)

// common errors.
var (
	errInvalidCLSignerKey       = errors.New("cl_signer_key_manager: invalid cred def key")
	errInvalidCLSignerKeyFormat = errors.New("cl_signer_key_manager: invalid cred def key format")
	errInvalidKeyUrsa           = errors.New("cl_signer_key_manager: can not create Ursa cred def key")
)

// clSignerKeyManager is an implementation of KeyManager interface for CL signatures/proofs.
// It generates new CredDefPrivateKeys and produces new instances of CLSigner subtle.
type clSignerKeyManager struct{}

// Сreates a new clSignerKeyManager.
func newCLSignerKeyManager() *clSignerKeyManager {
	return new(clSignerKeyManager)
}

// Primitive creates a CL Signer subtle for the given serialized CredDefPrivateKey proto.
func (km *clSignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidCLSignerKey
	}

	key := new(clpb.CLCredDefPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKey.Error()+": invalid proto: %w", err)
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKey.Error()+": %w", err)
	}

	clSigner, err := clsubtle.NewCLSigner(
		key.KeyValue,
		key.PublicKey.KeyValue,
		key.PublicKey.KeyCorrectnessProof,
		key.PublicKey.Params.Attrs,
	)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKey.Error()+": invalid ursa key: %w", err)
	}

	return clSigner, nil
}

// NewKey creates a new key according to the specification of CLCredDefPrivateKey format.
// nolint: funlen
func (km *clSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidCLSignerKeyFormat
	}

	// 1. Unmarshal to KeyFormat
	keyFormat := new(clpb.CLCredDefKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKeyFormat.Error()+": invalid proto: %w", err)
	}

	err = validateKeyFormat(keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKeyFormat.Error()+": %w", err)
	}

	// 2. Create Credentials Schema
	schema, nonSchema, err := ursautil.BuildSchema(keyFormat.Params.Attrs)
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": %w", err)
	}

	defer schema.Free()    // nolint: errcheck
	defer nonSchema.Free() // nolint: errcheck

	// 4. Create CredDef
	credDef, err := ursa.NewCredentialDef(schema, nonSchema, false)
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": %w", err)
	}

	defer credDef.PrivKey.Free()             // nolint: errcheck
	defer credDef.PubKey.Free()              // nolint: errcheck
	defer credDef.KeyCorrectnessProof.Free() // nolint: errcheck

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
		Version:  clSignerKeyVersion,
		KeyValue: privKeyBytes,
		PublicKey: &clpb.CLCredDefPublicKey{
			Version:             clSignerKeyVersion,
			Params:              keyFormat.Params,
			KeyValue:            pubKeyBytes,
			KeyCorrectnessProof: correctnessProofBytes,
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of CLCredDefPrivateKey Format.
// It should be used solely by the key management API.
func (km *clSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKeyFormat.Error()+": invalid proto: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         clSignerKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *clSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(clpb.CLCredDefPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKey.Error()+": invalid proto: %w", err)
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKey.Error()+": invalid proto: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         clSignerKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *clSignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == clSignerKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *clSignerKeyManager) TypeURL() string {
	return clSignerKeyTypeURL
}

// validateKey validates the given CLCredDefPrivateKey.
func (km *clSignerKeyManager) validateKey(key *clpb.CLCredDefPrivateKey) error {
	err := keyset.ValidateKeyVersion(key.Version, clSignerKeyVersion)
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
