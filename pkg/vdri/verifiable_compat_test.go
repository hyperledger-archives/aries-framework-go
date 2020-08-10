/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

func Test_LDProofs_Compatibility(t *testing.T) {
	t.Run("did:peer", func(t *testing.T) {
		alice := agent(t)
		alicePeerDID := createPeerDIDLikeDIDExchangeService(t, alice)
		require.NotEmpty(t, alicePeerDID.Authentication)

		verKey := alicePeerDID.Authentication[0].PublicKey
		require.NotNil(t, verKey)

		// alice self-issues a VC
		expectedVC := universityDegreeVC()

		now := time.Now()

		err := expectedVC.AddLinkedDataProof(
			&verifiable.LinkedDataProofContext{
				SignatureType: ed25519signature2018.SignatureType,
				Suite: ed25519signature2018.New(suite.WithSigner(
					&legacySigner{
						verkey: verKey.ID,
						ks:     alice.Signer(),
					},
				)),
				SignatureRepresentation: verifiable.SignatureJWS,
				Created:                 &now,
				VerificationMethod:      fmt.Sprintf("%s%s", alicePeerDID.ID, verKey.ID),
				Challenge:               uuid.New().String(),
				Domain:                  uuid.New().String(),
				Purpose:                 "authentication",
			},
		)
		require.NoError(t, err)

		// alice encloses her VC in a VP
		expectedVP, err := expectedVC.Presentation()
		require.NoError(t, err)

		err = expectedVP.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType: ed25519signature2018.SignatureType,
			Suite: ed25519signature2018.New(suite.WithSigner(
				&legacySigner{
					verkey: verKey.ID,
					ks:     alice.Signer(),
				},
			)),
			SignatureRepresentation: verifiable.SignatureJWS,
			Created:                 &now,
			VerificationMethod:      fmt.Sprintf("%s%s", alicePeerDID.ID, verKey.ID),
			Challenge:               uuid.New().String(),
			Domain:                  uuid.New().String(),
			Purpose:                 "authentication",
		})
		require.NoError(t, err)

		// alice wires her VP and DID to Bob
		aliceVPBits, err := json.Marshal(expectedVP)
		require.NoError(t, err)

		alicePeerDIDBits, err := alicePeerDID.JSONBytes()
		require.NoError(t, err)

		bob := agent(t)

		// bob parses and stores alice's DID
		actualPeerDID, err := did.ParseDocument(alicePeerDIDBits)
		require.NoError(t, err)

		err = bob.VDRIRegistry().Store(actualPeerDID)
		require.NoError(t, err)

		// bob parses alice's VP
		actualVP, err := verifiable.ParsePresentation(
			aliceVPBits,
			verifiable.WithPresPublicKeyFetcher(verifiable.NewDIDKeyResolver(bob.VDRIRegistry()).PublicKeyFetcher()))
		require.NoError(t, err)

		require.Equal(t, expectedVP.Context, actualVP.Context)
		require.Equal(t, expectedVP.Type, actualVP.Type)

		actualVCBits, err := actualVP.MarshalledCredentials()
		require.NoError(t, err)
		require.Len(t, actualVCBits, 1)

		// bob parses the VCs enclosed in alice's VP
		actualVC, err := verifiable.ParseCredential(
			actualVCBits[0],
			verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(bob.VDRIRegistry()).PublicKeyFetcher()))
		require.NoError(t, err)

		require.Equal(t, expectedVC.Context, actualVC.Context)
		require.Equal(t, expectedVC.Types, actualVC.Types)
	})
}

func agent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

func createPeerDIDLikeDIDExchangeService(t *testing.T, a *context.Provider) *did.Doc {
	t.Helper()

	peerDID, err := a.VDRIRegistry().Create(
		"peer",
		vdri.WithServiceEndpoint("http://example.com/didcomm"),
	)
	require.NoError(t, err)

	return peerDID
}

func universityDegreeVC() *verifiable.Credential {
	return &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		ID: "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		Issuer: verifiable.Issuer{
			ID: "did:web:vc.transmute.world",
			CustomFields: map[string]interface{}{
				"name": "Transmute University",
			},
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		Subject: &verifiable.Subject{
			ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
			CustomFields: map[string]interface{}{
				"degree": map[string]string{
					"type":   "BachelorDegree",
					"degree": "MIT",
				},
				"name":   "Jayden Doe",
				"spouse": "Bob Doe",
			},
		},
	}
}

type legacySigner struct {
	verkey string
	ks     legacykms.Signer
}

func (s *legacySigner) Sign(message []byte) ([]byte, error) {
	return s.ks.SignMessage(message, s.verkey)
}
