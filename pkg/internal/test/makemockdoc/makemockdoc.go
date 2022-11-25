/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package makemockdoc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	// DefaultKID the KID of the mock doc's verification method.
	DefaultKID                 = "#key-1"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	jsonWebKey2020             = "JsonWebKey2020"
)

// MakeMockDoc creates a key in the given KMS and returns a mock DID Doc with a verification method using the given key.
func MakeMockDoc(t *testing.T, keyManager kms.KeyManager, docDID string, keyType kms.KeyType) *did.Doc {
	t.Helper()

	_, pkb, err := keyManager.CreateAndExportPubKeyBytes(keyType)
	require.NoError(t, err)

	var pkJWK *jwk.JWK

	var vm *did.VerificationMethod

	if keyType == kms.ED25519Type {
		vm = &did.VerificationMethod{
			ID:         DefaultKID,
			Controller: docDID,
			Type:       ed25519VerificationKey2018,
			Value:      pkb,
		}
	} else {
		pkJWK, err = jwkkid.BuildJWK(pkb, keyType)
		require.NoError(t, err)

		pkJWK.Algorithm = "ECDSA"

		vm, err = did.NewVerificationMethodFromJWK(DefaultKID, jsonWebKey2020, docDID, pkJWK)
		require.NoError(t, err)
	}

	newDoc := &did.Doc{
		ID: docDID,
		AssertionMethod: []did.Verification{
			{
				VerificationMethod: *vm,
				Relationship:       did.AssertionMethod,
			},
		},
		VerificationMethod: []did.VerificationMethod{
			*vm,
		},
	}

	return newDoc
}
