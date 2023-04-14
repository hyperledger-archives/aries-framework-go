//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"testing"

	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/internal/ursautil"
)

// NewTestCLSigner returns test CLSigner.
func NewTestCLSigner(t *testing.T) *CLSigner {
	signer, err := NewCLSigner(CreateCredentialDefinitionJSON(t))
	require.NoError(t, err)

	return signer
}

// NewTestCLBlinder returns test CLBlinder.
func NewTestCLBlinder(t *testing.T) *CLBlinder {
	blinder, err := NewCLBlinder(CreateMasterSecretKeyJSON(t))
	require.NoError(t, err)

	return blinder
}

// NewTestValues returns test values.
func NewTestValues(t *testing.T) map[string]interface{} {
	return map[string]interface{}{"attr1": 5, "attr2": "aaa"} // nolint: gomnd
}

// NewBlindedSecretsWithNonces returns test blinded secrets and generated nonces.
func NewBlindedSecretsWithNonces(
	t *testing.T,
	credDefPubKey *ursa.CredentialDefPubKey,
	credDefCorrectnessProof *ursa.CredentialDefKeyCorrectnessProof,
	blindedVals *ursa.CredentialValues,
) ([]byte, []byte, []byte, []byte) {
	offerNonce, err := ursa.NewNonce()
	require.NoError(t, err)
	blindedSecrets, err := ursa.BlindCredentialSecrets(credDefPubKey, credDefCorrectnessProof, offerNonce, blindedVals)
	assert.NoError(t, err)
	requestNonce, err := ursa.NewNonce()
	require.NoError(t, err)

	secrets, err := blindedSecrets.Handle.ToJSON()
	require.NoError(t, err)
	proof, err := blindedSecrets.CorrectnessProof.ToJSON()
	require.NoError(t, err)
	offerNonceJSON, err := offerNonce.ToJSON()
	require.NoError(t, err)
	requestNonceJSON, err := requestNonce.ToJSON()
	require.NoError(t, err)

	return secrets, proof, offerNonceJSON, requestNonceJSON
}

// CreateMasterSecretKeyJSON returns test Master Secret key.
func CreateMasterSecretKeyJSON(t *testing.T) []byte {
	masterSecret, err := ursa.NewMasterSecret()
	require.NoError(t, err)

	defer masterSecret.Free() // nolint: errcheck

	masterSecretJSON, err := masterSecret.ToJSON()
	require.NoError(t, err)

	return masterSecretJSON
}

// CreateCredentialDefinitionJSON returns test CredDef keys and attrs.
func CreateCredentialDefinitionJSON(t *testing.T) ([]byte, []byte, []byte, []string) {
	attrs := []string{"attr1", "attr2"}
	schema, nonSchema, err := ursautil.BuildSchema(attrs)
	require.NoError(t, err)

	defer schema.Free()    // nolint: errcheck
	defer nonSchema.Free() // nolint: errcheck

	credDef, err := ursa.NewCredentialDef(schema, nonSchema, false)
	require.NoError(t, err)

	defer credDef.PubKey.Free()              // nolint: errcheck
	defer credDef.PrivKey.Free()             // nolint: errcheck
	defer credDef.KeyCorrectnessProof.Free() // nolint: errcheck

	privKeyJSON, err := credDef.PrivKey.ToJSON()
	require.NoError(t, err)
	pubKeyJSON, err := credDef.PubKey.ToJSON()
	require.NoError(t, err)
	proofJSON, err := credDef.KeyCorrectnessProof.ToJSON()
	require.NoError(t, err)

	return privKeyJSON, pubKeyJSON, proofJSON, attrs
}
