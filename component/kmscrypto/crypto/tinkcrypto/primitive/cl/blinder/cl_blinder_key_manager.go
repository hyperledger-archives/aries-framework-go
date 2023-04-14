//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blinder

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
	"google.golang.org/protobuf/proto"

	clsubtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/subtle"
	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
)

const (
	clBlinderKeyVersion = 0
	clBlinderKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.CLMasterSecretKey"
)

// common errors.
var (
	errInvalidCLBlinderKey       = errors.New("cl_blinder_key_manager: invalid master secret key")
	errInvalidCLBlinderKeyFormat = errors.New("cl_blinder_key_manager: invalid master secret key format")
	errInvalidKeyUrsa            = errors.New("cl_blinder_key_manager: can not create Ursa master secret key")
)

// clBlinderKeyManager is an implementation of KeyManager interface for CL signatures/proofs.
// It generates new Master Secrets and produces new instances of CLBlinder subtle.
type clBlinderKeyManager struct{}

// Сreates a new clBlinderKeyManager.
func newCLBlinderKeyManager() *clBlinderKeyManager {
	return new(clBlinderKeyManager)
}

// Primitive creates a CL Blinder subtle for the given serialized Master Secret proto.
func (km *clBlinderKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidCLBlinderKey
	}

	key := new(clpb.CLMasterSecret)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLBlinderKey.Error()+": invalid proto: %w", err)
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLBlinderKey.Error()+": %w", err)
	}

	clBlinder, err := clsubtle.NewCLBlinder(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLBlinderKey.Error()+": invalid ursa key: %w", err)
	}

	return clBlinder, nil
}

// NewKey creates a new key according to the specification of CLMasterSecretKeyFormat format.
func (km *clBlinderKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if serializedKeyFormat == nil {
		return nil, errInvalidCLBlinderKeyFormat
	}

	// 1. Unmarshal to KeyFormat
	keyFormat := new(clpb.CLMasterSecretKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLBlinderKeyFormat.Error()+": invalid proto: %w", err)
	}

	err = km.validateKeyFormat(keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLBlinderKey.Error()+": %w", err)
	}

	// 2. Create Master Secret
	ms, err := ursa.NewMasterSecret()
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": %w", err)
	}

	defer ms.Free() // nolint: errcheck

	// 3. serialize keys to JSONs
	msBytes, err := ms.ToJSON()
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyUrsa.Error()+": can not convert master secret to JSON: %w", err)
	}

	return &clpb.CLMasterSecret{
		Version:  clBlinderKeyVersion,
		KeyValue: msBytes,
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of CLMasterSecret Format.
// It should be used solely by the key management API.
func (km *clBlinderKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLBlinderKeyFormat.Error()+": invalid proto: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         clBlinderKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *clBlinderKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == clBlinderKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *clBlinderKeyManager) TypeURL() string {
	return clBlinderKeyTypeURL
}

// validateKey validates the given CLCredDefPrivateKey.
func (km *clBlinderKeyManager) validateKey(key *clpb.CLMasterSecret) error {
	err := keyset.ValidateKeyVersion(key.Version, clBlinderKeyVersion)
	if err != nil {
		return fmt.Errorf("invalid key version: %w", err)
	}

	return nil
}

func (km *clBlinderKeyManager) validateKeyFormat(format *clpb.CLMasterSecretKeyFormat) error {
	return nil
}
