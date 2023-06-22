/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vmparse

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

const (
	jsonWebKey2020             = "JsonWebKey2020"
	jwsVerificationKey2020     = "JwsVerificationKey2020"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

// VMToBytesTypeCrv parses a DID doc Verification Method and returns the public key bytes, KMS KeyType, and key Curve.
func VMToBytesTypeCrv(vm *did.VerificationMethod) ([]byte, kms.KeyType, string, error) {
	switch vm.Type {
	case ed25519VerificationKey2018:
		return vm.Value, kms.ED25519Type, "Ed25519", nil
	case jsonWebKey2020, jwsVerificationKey2020:
		k := vm.JSONWebKey()

		kb, err := k.PublicKeyBytes()
		if err != nil {
			return nil, "", "", fmt.Errorf("getting []byte key for verification key: %w", err)
		}

		kt, err := k.KeyType()
		if err != nil {
			return nil, "", "", fmt.Errorf("getting kms.KeyType of verification key: %w", err)
		}

		return kb, kt, k.Crv, nil
	default:
		return nil, "", "", fmt.Errorf("vm.Type '%s' not supported", vm.Type)
	}
}

// VMToTypeCrv parses a DID doc Verification Method and returns the KMS KeyType, and key Curve.
func VMToTypeCrv(vm *did.VerificationMethod) (kms.KeyType, string, error) {
	switch vm.Type {
	case ed25519VerificationKey2018:
		return kms.ED25519Type, "Ed25519", nil
	case jsonWebKey2020, jwsVerificationKey2020:
		k := vm.JSONWebKey()

		kt, err := k.KeyType()
		if err != nil {
			return "", "", fmt.Errorf("getting kms.KeyType of verification key: %w", err)
		}

		return kt, k.Crv, nil
	default:
		return "", "", fmt.Errorf("vm.Type '%s' not supported", vm.Type)
	}
}
