/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/ed25519"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	vdrdoc "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
)

const (
	didKey         = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	didKeyID       = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll
	agreementKeyID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" //nolint:lll

	pubKeyBase58       = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
	keyAgreementBase58 = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
)

func TestBuild(t *testing.T) {
	t.Run("validate did:key compliance with generic syntax", func(t *testing.T) {
		v := New()

		pubKey := &vdrdoc.PublicKey{
			Type: ed25519VerificationKey2018,
			JWK:  gojose.JSONWebKey{Key: ed25519.PublicKey(base58.Decode(pubKeyBase58))},
		}

		docResolution, err := v.Build(nil, create.WithPublicKey(pubKey))
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		d, err := did.Parse(docResolution.DIDDocument.ID)
		require.NoError(t, err)
		require.NotNil(t, d)
	})

	t.Run("build with default key type", func(t *testing.T) {
		v := New()

		pubKey := &vdrdoc.PublicKey{
			Type: ed25519VerificationKey2018,
			JWK:  gojose.JSONWebKey{Key: ed25519.PublicKey(base58.Decode(pubKeyBase58))},
		}

		docResolution, err := v.Build(nil, create.WithPublicKey(pubKey))
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertDoc(t, docResolution.DIDDocument)
	})
}

func assertDoc(t *testing.T, doc *did.Doc) {
	// validate @context
	require.Equal(t, schemaV1, doc.Context[0])

	// validate id
	require.Equal(t, didKey, doc.ID)

	expectedPubKey := &did.VerificationMethod{
		ID:         didKeyID,
		Type:       ed25519VerificationKey2018,
		Controller: didKey,
		Value:      base58.Decode(pubKeyBase58),
	}

	expectedKeyAgreement := &did.VerificationMethod{
		ID:         agreementKeyID,
		Type:       x25519KeyAgreementKey2019,
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
