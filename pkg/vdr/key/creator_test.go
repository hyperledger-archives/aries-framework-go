/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/ed25519"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

func TestBuild(t *testing.T) {
	const (
		pubKeyBase58Ed25519 = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
	)

	t.Run("validate did:key compliance with generic syntax", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  ed25519VerificationKey2018,
			Value: ed25519.PublicKey(base58.Decode(pubKeyBase58Ed25519)),
		}

		docResolution, err := v.Create(nil, &did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		d, err := did.Parse(docResolution.DIDDocument.ID)
		require.NoError(t, err)
		require.NotNil(t, d)
	})

	t.Run("build with default key type", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  ed25519VerificationKey2018,
			Value: base58.Decode(pubKeyBase58Ed25519),
		}

		docResolution, err := v.Create(nil, &did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertEd25519Doc(t, docResolution.DIDDocument)
	})
}

func assertEd25519Doc(t *testing.T, doc *did.Doc) {
	const (
		didKey         = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		didKeyID       = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll
		agreementKeyID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" //nolint:lll

		pubKeyBase58       = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
		keyAgreementBase58 = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, ed25519VerificationKey2018, pubKeyBase58,
		agreementKeyID, x25519KeyAgreementKey2019, keyAgreementBase58)
}

func assertBase58Doc(t *testing.T, doc *did.Doc, didKey, didKeyID, didKeyType, pubKeyBase58 string) {
	assertDualBase58Doc(t, doc, didKey, didKeyID, didKeyType, pubKeyBase58, didKeyID, didKeyType, pubKeyBase58)
}

func assertDualBase58Doc(t *testing.T, doc *did.Doc, didKey, didKeyID, didKeyType, pubKeyBase58,
	agreementKeyID, keyAgreementType, keyAgreementBase58 string) {
	// validate @context
	require.Equal(t, schemaV1, doc.Context[0])

	// validate id
	require.Equal(t, didKey, doc.ID)

	expectedPubKey := &did.VerificationMethod{
		ID:         didKeyID,
		Type:       didKeyType,
		Controller: didKey,
		Value:      base58.Decode(pubKeyBase58),
	}

	expectedKeyAgreement := &did.VerificationMethod{
		ID:         agreementKeyID,
		Type:       keyAgreementType,
		Controller: didKey,
		Value:      base58.Decode(keyAgreementBase58),
	}

	// validate publicKey
	assertPubKey(t, expectedPubKey, &doc.VerificationMethod[0])

	// validate assertionMethod
	assertPubKey(t, expectedPubKey, &doc.AssertionMethod[0].VerificationMethod)

	// validate authentication
	assertPubKey(t, expectedPubKey, &doc.Authentication[0].VerificationMethod)

	// validate capabilityDelegation
	assertPubKey(t, expectedPubKey, &doc.CapabilityDelegation[0].VerificationMethod)

	// validate capabilityInvocation
	assertPubKey(t, expectedPubKey, &doc.CapabilityInvocation[0].VerificationMethod)

	// validate keyAgreement
	assertPubKey(t, expectedKeyAgreement, &doc.KeyAgreement[0].VerificationMethod)
}

func assertPubKey(t *testing.T, expectedPubKey, actualPubKey *did.VerificationMethod) {
	require.NotNil(t, actualPubKey)
	require.Equal(t, expectedPubKey.ID, actualPubKey.ID)
	require.Equal(t, expectedPubKey.Type, actualPubKey.Type)
	require.Equal(t, expectedPubKey.Controller, actualPubKey.Controller)
	require.Equal(t, expectedPubKey.Value, actualPubKey.Value)
}
