//go:build ursa
// +build ursa

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ursa

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	bld "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/blinder"
	sgn "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cl"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
)

func TestCL(t *testing.T) {
	km := &mockkms.KeyManager{}
	c := &tinkcrypto.Crypto{}
	provider := newProvider(km, c)

	values := map[string]interface{}{"attr1": 5, "attr2": "aaa"}
	values2 := map[string]interface{}{"attr3": 5, "attr4": "aaa"}

	presentaionItems := []*cl.PresentationRequestItem{{
		RevealedAttrs: []string{"attr2"},
		Predicates: []*cl.Predicate{
			{
				PType: "GE",
				Attr:  "attr1",
				Value: 4,
			},
		},
	}}

	var (
		issuer   *Issuer
		prover   *Prover
		verifier *Verifier

		credDef    *cl.CredentialDefinition
		offer      *cl.CredentialOffer
		request    *cl.CredentialRequest
		credential *cl.Credential

		originalSignature []byte

		presentation *cl.PresentationRequest
		proof        *cl.Proof
	)

	t.Run("test CL services creation", func(t *testing.T) {
		var err error

		issKh, issPubKey := createAndExportSignerKey(t, []string{"attr1", "attr2"})
		km.GetKeyValue = issKh
		km.ExportPubKeyBytesValue = issPubKey
		km.ExportPubKeyTypeValue = kms.CLCredDefType

		issuer, err = NewIssuer(provider, "credDefKID", []string{"attr1", "attr2"})
		require.NoError(t, err)

		prvKh := createBlinderKey(t)
		km.GetKeyValue = prvKh

		prover, err = NewProver(provider, "msKID")
		require.NoError(t, err)

		verifier, err = NewVerifier()
		require.NoError(t, err)
	})

	t.Run("test CL issue credential flow", func(t *testing.T) {
		var err error

		// 0. Issuer expose CredDef
		credDef, err = issuer.GetCredentialDefinition()
		require.NoError(t, err)
		require.NotEmpty(t, credDef.CredPubKey)
		require.NotEmpty(t, credDef.CredDefCorrectnessProof)

		// 1. Issuer offers credential
		offer, err = issuer.OfferCredential()
		require.NoError(t, err)
		require.NotEmpty(t, offer.Nonce)

		// 2. Prover requests credential
		request, err = prover.RequestCredential(offer, credDef, "proverDID")
		require.NoError(t, err)
		require.NotEmpty(t, request.Nonce)
		require.NotEmpty(t, request.ProverID)
		require.NotEmpty(t, request.BlindedCredentialSecrets)

		// 3. Issuer issues credential
		credential, err = issuer.IssueCredential(values, request, offer)
		require.NoError(t, err)
		require.NotEmpty(t, credential.Signature)
		require.NotEmpty(t, credential.SigProof)
		require.NotEmpty(t, credential.Values)

		// 4. Prover verifies credential
		originalSignature = credential.Signature

		err = prover.ProcessCredential(credential, request, credDef)
		require.NoError(t, err)
		require.NotEmpty(t, credential.Signature)
		require.NotEmpty(t, credential.SigProof)
		require.NotEmpty(t, credential.Values)

		require.NotEqual(t, originalSignature, credential.Signature)
	})

	t.Run("test CL present proof flow", func(t *testing.T) {
		var err error

		// 1. Verifier makes presentation request
		presentation, err = verifier.RequestPresentation(presentaionItems)
		require.NoError(t, err)
		require.NotEmpty(t, presentation.Items)
		require.NotEmpty(t, presentation.Nonce)

		// 2. Prover creates proof accordingly
		proof, err = prover.CreateProof(presentation, []*cl.Credential{credential}, []*cl.CredentialDefinition{credDef})
		require.NoError(t, err)
		require.NotEmpty(t, proof.Proof)

		// 3. Verifier verifies resulting proof
		err = verifier.VerifyProof(proof, presentation, []*cl.CredentialDefinition{credDef})
		require.NoError(t, err)
	})

	t.Run("test CL failures", func(t *testing.T) {
		var err error

		issKh2, issPubKey2 := createAndExportSignerKey(t, []string{"attr3", "attr4"})
		km.GetKeyValue = issKh2
		km.ExportPubKeyBytesValue = issPubKey2
		km.ExportPubKeyTypeValue = kms.CLCredDefType

		issuer2, err := NewIssuer(provider, "credDefKID2", []string{"attr3", "attr4"})
		require.NoError(t, err)
		credDef2, err := issuer2.GetCredentialDefinition()
		require.NoError(t, err)

		// Issuer fails to issue credential for unknown credDef
		_, err = issuer2.IssueCredential(values, request, offer)
		require.Error(t, err)

		// Issuer fails to issue credential for invalid values
		_, err = issuer.IssueCredential(values2, request, offer)
		require.Error(t, err)

		// Prover fails to process credential with unmatched credDef
		err = prover.ProcessCredential(credential, request, credDef2)
		require.Error(t, err)

		// Prover fails to create proof with unmatched credDefs
		_, err = prover.CreateProof(presentation, []*cl.Credential{credential}, []*cl.CredentialDefinition{credDef2})
		require.Error(t, err)

		// Verifier fails to verify proof for unprocessed credential
		unprocessed := &cl.Credential{
			Signature: originalSignature,
			SigProof:  credential.SigProof,
			Values:    credential.Values,
		}

		invalid, err := prover.CreateProof(presentation, []*cl.Credential{unprocessed}, []*cl.CredentialDefinition{credDef})
		require.NoError(t, err)

		err = verifier.VerifyProof(invalid, presentation, []*cl.CredentialDefinition{credDef})
		require.Error(t, err)

		//  Verifier fails to verify proof for other credDef
		err = verifier.VerifyProof(proof, presentation, []*cl.CredentialDefinition{credDef2})
		require.Error(t, err)
	})
}

func createAndExportSignerKey(t *testing.T, attrs []string) (*keyset.Handle, []byte) {
	kh, err := keyset.NewHandle(sgn.CredDefKeyTemplate(attrs))
	require.NoError(t, err)

	pKh, err := kh.Public()
	require.NoError(t, err)

	pubKey, err := sgn.ExportCredDefPubKey(pKh)
	require.NoError(t, err)

	return kh, pubKey
}

func createBlinderKey(t *testing.T) *keyset.Handle {
	kh, err := keyset.NewHandle(bld.MasterSecretKeyTemplate())
	require.NoError(t, err)

	return kh
}

type mockProvider struct {
	km kms.KeyManager
	cr crypto.Crypto
}

func (p *mockProvider) KMS() kms.KeyManager {
	return p.km
}

func (p *mockProvider) Crypto() crypto.Crypto {
	return p.cr
}

func newProvider(km kms.KeyManager, cr crypto.Crypto) *mockProvider {
	return &mockProvider{
		km: km,
		cr: cr,
	}
}
