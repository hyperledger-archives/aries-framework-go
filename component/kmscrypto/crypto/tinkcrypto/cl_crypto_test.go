//go:build ursa
// +build ursa

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
	"github.com/stretchr/testify/require"

	bld "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/blinder"
	sgn "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/signer"
)

func TestCL(t *testing.T) {
	c := Crypto{}

	var (
		sgnKh *keyset.Handle
		bldKh *keyset.Handle
		pubKh *keyset.Handle

		pubKey           []byte
		correctnessProof []byte
	)

	t.Run("test CL keys creation", func(t *testing.T) {
		var err error

		sgnKh, err = keyset.NewHandle(sgn.CredDefKeyTemplate([]string{"attr1", "attr2"}))
		require.NoError(t, err)

		bldKh, err = keyset.NewHandle(bld.MasterSecretKeyTemplate())
		require.NoError(t, err)

		pubKh, err = sgnKh.Public()
		require.NoError(t, err)

		pubKey, err = sgn.ExportCredDefPubKey(pubKh)
		require.NoError(t, err)
	})

	t.Run("test CL correctness proof", func(t *testing.T) {
		var err error
		correctnessProof, err = c.GetCorrectnessProof(sgnKh)
		require.NoError(t, err)
		require.NotEmpty(t, correctnessProof)
	})

	t.Run("test CL invalid inputs", func(t *testing.T) {
		var err error

		// Invalid key handles

		// Signer
		_, err = c.GetCorrectnessProof(nil)
		require.EqualError(t, err, errBadKeyHandleFormat.Error())
		_, err = c.GetCorrectnessProof("not a handle")
		require.EqualError(t, err, errBadKeyHandleFormat.Error())
		_, _, err = c.SignWithSecrets([]string{"not a handle"}, map[string]interface{}{}, nil, nil, nil, "")
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		_, err = c.GetCorrectnessProof(bldKh)
		require.Error(t, err)
		_, _, err = c.SignWithSecrets(bldKh, map[string]interface{}{}, nil, nil, nil, "")
		require.Error(t, err)

		// Blinder
		_, err = c.Blind(nil, map[string]interface{}{})
		require.EqualError(t, err, errBadKeyHandleFormat.Error())
		_, err = c.Blind("not a handle", map[string]interface{}{})
		require.EqualError(t, err, errBadKeyHandleFormat.Error())
		_, err = c.Blind([]string{"not a handle"}, nil, nil)
		require.EqualError(t, err, errBadKeyHandleFormat.Error())

		_, err = c.Blind(sgnKh, map[string]interface{}{})
		require.Error(t, err)
	})

	t.Run("test CL blind", func(t *testing.T) {
		// Should blind only master secret if no values provided
		blindedMs, err := c.Blind(bldKh)
		require.NoError(t, err)
		require.NotEmpty(t, blindedMs)

		// Should blind values
		blindedVals, err := c.Blind(bldKh,
			map[string]interface{}{"attr1": 1, "attr2": "aaa"},
		)
		require.NoError(t, err)
		require.NotEmpty(t, blindedVals)

		// Should blind multiple values sets from with different schemas
		blindedMultiVals, err := c.Blind(bldKh,
			map[string]interface{}{"attr1": 1, "attr2": "aaa"},
			map[string]interface{}{"attr3": 3, "attr4": "bbb"},
		)
		require.NoError(t, err)
		require.NotEmpty(t, blindedMultiVals)
	})

	t.Run("test CL sign with secrets", func(t *testing.T) {
		blindedVals, err := c.Blind(bldKh,
			map[string]interface{}{"attr1": 1, "attr2": "aaa"},
		)
		require.NoError(t, err)
		require.NotEmpty(t, blindedVals)

		secrets, secretsProof, offerNonce, requestNonce := generateBlindedSecretsWithNonces(t,
			pubKey,
			correctnessProof,
			blindedVals[0],
		)

		// Should sign with secrets and return signature and correctness proof
		sig, sigProof, err := c.SignWithSecrets(sgnKh,
			map[string]interface{}{"attr1": 1, "attr2": "aaa"},
			secrets,
			secretsProof,
			[][]byte{offerNonce, requestNonce},
			"did:example:id",
		)
		require.NoError(t, err)
		require.NotEmpty(t, sig)
		require.NotEmpty(t, sigProof)

		// Should fail to sign values for another credDef
		_, _, err = c.SignWithSecrets(sgnKh,
			map[string]interface{}{"attr3": 3, "attr4": "bbb"},
			secrets,
			secretsProof,
			[][]byte{offerNonce, requestNonce},
			"did:example:id",
		)
		require.Error(t, err)
	})
}

func generateBlindedSecretsWithNonces(
	t *testing.T,
	pubKey []byte,
	correctnessProof []byte,
	blindedVals []byte,
) ([]byte, []byte, []byte, []byte) {
	_pubKey, err := ursa.CredentialPublicKeyFromJSON(pubKey)
	require.NoError(t, err)
	_correctnessProof, err := ursa.CredentialKeyCorrectnessProofFromJSON(correctnessProof)
	require.NoError(t, err)
	_blindedVals, err := ursa.CredentialValuesFromJSON(blindedVals)
	require.NoError(t, err)

	_offerNonce, err := ursa.NewNonce()
	require.NoError(t, err)
	_blindedSecrets, err := ursa.BlindCredentialSecrets(_pubKey, _correctnessProof, _offerNonce, _blindedVals)
	require.NoError(t, err)
	_requestNonce, err := ursa.NewNonce()
	require.NoError(t, err)

	secrets, err := _blindedSecrets.Handle.ToJSON()
	require.NoError(t, err)
	secretsProof, err := _blindedSecrets.CorrectnessProof.ToJSON()
	require.NoError(t, err)
	offerNonce, err := _offerNonce.ToJSON()
	require.NoError(t, err)
	requestNonce, err := _requestNonce.ToJSON()
	require.NoError(t, err)

	return secrets, secretsProof, offerNonce, requestNonce
}
