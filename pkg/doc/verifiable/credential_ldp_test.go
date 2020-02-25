/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
)

func TestNewCredentialFromLinkedDataProof(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	suite := ed25519signature2018.New(ed25519signature2018.WithSigner(getEd25519TestSigner(privKey)))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: SignatureProofValue,
		Suite:                   suite,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, _, err := NewCredential([]byte(validCredential))
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext)
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	vcWithLdp, _, err := NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(suite),
		WithPublicKeyFetcher(SingleKey([]byte(pubKey))))
	r.NoError(err)
	r.Equal(vc, vcWithLdp)
}

func TestCredential_AddLinkedDataProof(t *testing.T) {
	r := require.New(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	t.Run("Add a valid JWS Linked Data proof to VC", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		r.NoError(err)

		originalVCMap, err := toMap(vc)
		r.NoError(err)

		err = vc.AddLinkedDataProof(&LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			SignatureRepresentation: SignatureJWS,
			Suite:                   ed25519signature2018.New(ed25519signature2018.WithSigner(getEd25519TestSigner(privKey))),
		})
		r.NoError(err)

		vcMap, err := toMap(vc)
		r.NoError(err)

		r.Contains(vcMap, "proof")
		vcProof := vcMap["proof"]
		vcProofMap, ok := vcProof.(map[string]interface{})
		r.True(ok)
		r.Contains(vcProofMap, "created")
		r.Contains(vcProofMap, "jws")
		r.Equal("Ed25519Signature2018", vcProofMap["type"])

		// check that only "proof" element was added as a result of AddLinkedDataProof().
		delete(vcMap, "proof")
		r.Equal(originalVCMap, vcMap)
	})

	t.Run("Add invalid Linked Data proof to VC", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.CustomFields = map[string]interface{}{
			"invalidField": make(chan int),
		}

		err = vc.AddLinkedDataProof(&LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			SignatureRepresentation: SignatureProofValue,
			Suite:                   ed25519signature2018.New(ed25519signature2018.WithSigner(getEd25519TestSigner(privKey))),
		})
		r.Error(err)

		vc.CustomFields = nil
		ldpContextWithMissingSignatureType := &LinkedDataProofContext{
			Suite:                   ed25519signature2018.New(ed25519signature2018.WithSigner(getEd25519TestSigner(privKey))),
			SignatureRepresentation: SignatureProofValue,
		}

		err = vc.AddLinkedDataProof(ldpContextWithMissingSignatureType)
		r.Error(err)
	})
}
