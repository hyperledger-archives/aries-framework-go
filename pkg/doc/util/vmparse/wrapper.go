/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vmparse

import (
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/did/util/vmparse"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// VMToBytesTypeCrv parses a DID doc Verification Method and returns the public key bytes, KMS KeyType, and key Curve.
func VMToBytesTypeCrv(vm *did.VerificationMethod) ([]byte, kms.KeyType, string, error) {
	return vmparse.VMToBytesTypeCrv(vm)
}

// VMToTypeCrv parses a DID doc Verification Method and returns the KMS KeyType, and key Curve.
func VMToTypeCrv(vm *did.VerificationMethod) (kms.KeyType, string, error) {
	return vmparse.VMToTypeCrv(vm)
}
