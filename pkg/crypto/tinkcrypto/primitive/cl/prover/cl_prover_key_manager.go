//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prover

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
	clProverKeyVersion = 0
	clProverKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.CLProverKey"
)

// common errors.
var (
	errInvalidCLProverKey       = errors.New("cl_prover_key_manager: invalid master secret key")
	errInvalidCLProverKeyFormat = errors.New("cl_prover_key_manager: invalid master secret key format")
	errInvalidKeyUrsa           = errors.New("cl_prover_key_manager: can not create Ursa master secret key")
)

// clProverKeyManager is an implementation of KeyManager interface for CL signatures/proofs.
// It generates new Master Secrets and produces new instances of CLProver subtle.
type clProverKeyManager struct{}

// Сreates a new clProverKeyManager.
func newCLProverKeyManager() *clProverKeyManager {
	return new(clProverKeyManager)
}

// Primitive creates a CL Prover subtle for the given serialized Master Secret proto.
func (km *clProverKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidCLProverKey
	}

	key := new(clpb.CLMasterSecret)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLProverKey.Error()+": invalid proto: %w", err)
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLProverKey.Error()+": %w", err)
	}

	clProver, err := clsubtle.NewCLProver(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLProverKey.Error()+": invalid ursa key: %w", err)
	}

	return clProver, nil
}

// NewKey creates a new key according to the specification of CLMasterSecretKeyFormat format.
func (km *clProverKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if serializedKeyFormat == nil {
		return nil, errInvalidCLProverKeyFormat
	}

	// 1. Unmarshal to KeyFormat
	keyFormat := new(clpb.CLMasterSecretKeyFormat)
	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLProverKeyFormat.Error()+": invalid proto: %w", err)
	}
	err = validateKeyFormat(keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLProverKey.Error()+": %w", err)
	}

	// 2. Create Master Secret
	ms, err := ursa.NewMasterSecret()
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": %w", err)
	}

	// 3. serialize keys to JSONs
	msBytes, err := ms.ToJSON()
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": can not convert master secret to JSON: %w", err)
	}

	return &clpb.CLMasterSecret{
		Version:  clProverKeyVersion,
		KeyValue: msBytes,
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of CLMasterSecret Format.
// It should be used solely by the key management API.
func (km *clProverKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLProverKeyFormat.Error()+": invalid proto: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         clProverKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *clProverKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == clProverKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *clProverKeyManager) TypeURL() string {
	return clProverKeyTypeURL
}

// validateKey validates the given CLCredDefPrivateKey
func (km *clProverKeyManager) validateKey(key *clpb.CLMasterSecret) error {
	err := keyset.ValidateKeyVersion(key.Version, clProverKeyVersion)
	if err != nil {
		return fmt.Errorf("invalid key version: %w", err)
	}
	return nil
}

func validateKeyFormat(format *clpb.CLMasterSecretKeyFormat) error {
	return nil
}
