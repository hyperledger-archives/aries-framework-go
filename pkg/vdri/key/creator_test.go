/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

const (
	didKey         = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	didKeyID       = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll
	agreementKeyID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" //nolint:lll

	pubKeyBase58       = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
	keyAgreementBase58 = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
)

func TestBuild(t *testing.T) {
	t.Run("validate not supported public key", func(t *testing.T) {
		v := New()

		pubKey := &vdriapi.PubKey{
			Type: "not-supported-type",
		}

		doc, err := v.Build(pubKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported public key type: not-supported-type")
		require.Nil(t, doc)
	})

	t.Run("validate did:key compliance with generic syntax", func(t *testing.T) {
		v := New()

		pubKey := &vdriapi.PubKey{
			Type:  ed25519VerificationKey2018,
			Value: pubKeyBase58,
		}

		doc, err := v.Build(pubKey)
		require.NoError(t, err)
		require.NotNil(t, doc)

		d, err := did.Parse(doc.ID)
		require.NoError(t, err)
		require.NotNil(t, d)
	})

	t.Run("build with default key type", func(t *testing.T) {
		v := New()

		pubKey := &vdriapi.PubKey{
			Type:  ed25519VerificationKey2018,
			Value: pubKeyBase58,
		}

		doc, err := v.Build(pubKey)
		require.NoError(t, err)
		require.NotNil(t, doc)

		assertDoc(t, doc)
	})
}

func assertDoc(t *testing.T, doc *did.Doc) {
	// validate @context
	require.Equal(t, schemaV1, doc.Context[0])

	// validate id
	require.Equal(t, didKey, doc.ID)

	expectedPubKey := &did.PublicKey{
		ID:         didKeyID,
		Type:       ed25519VerificationKey2018,
		Controller: didKey,
		Value:      base58.Decode(pubKeyBase58),
	}

	expectedKeyAgreement := &did.PublicKey{
		ID:         agreementKeyID,
		Type:       x25519KeyAgreementKey2019,
		Controller: didKey,
		Value:      base58.Decode(keyAgreementBase58),
	}

	// validate publicKey
	assertPubKey(t, expectedPubKey, &doc.PublicKey[0])

	// validate assertionMethod
	assertPubKey(t, expectedPubKey, &doc.AssertionMethod[0].PublicKey)

	// validate authentication
	assertPubKey(t, expectedPubKey, &doc.Authentication[0].PublicKey)

	// validate capabilityDelegation
	assertPubKey(t, expectedPubKey, &doc.CapabilityDelegation[0].PublicKey)

	// validate capabilityInvocation
	assertPubKey(t, expectedPubKey, &doc.CapabilityInvocation[0].PublicKey)

	// validate keyAgreement
	assertPubKey(t, expectedKeyAgreement, &doc.KeyAgreement[0].PublicKey)
}

func assertPubKey(t *testing.T, expectedPubKey, actualPubKey *did.PublicKey) {
	require.NotNil(t, actualPubKey)
	require.Equal(t, expectedPubKey.ID, actualPubKey.ID)
	require.Equal(t, expectedPubKey.Type, actualPubKey.Type)
	require.Equal(t, expectedPubKey.Controller, actualPubKey.Controller)
	require.Equal(t, expectedPubKey.Value, actualPubKey.Value)
}
