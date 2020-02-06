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

	suite := ed25519signature2018.New(ed25519signature2018.WithSigner(getSigner(privKey)))

	ldpContext := &LinkedDataProofContext{
		Creator:       "didID#keyID",
		SignatureType: "Ed25519Signature2018",
		Suite:         suite,
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

	r.NoError(err)
	r.Equal(vc, vcWithLdp)
}

func TestCredential_AddLinkedDataProof(t *testing.T) {
	r := require.New(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	ldpContext := &LinkedDataProofContext{
		Creator:       "John",
		SignatureType: "Ed25519Signature2018",
		Suite:         ed25519signature2018.New(ed25519signature2018.WithSigner(getSigner(privKey))),
	}

	t.Run("Add a valid Linked Data proof to VC", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		r.NoError(err)

		originalVCMap, err := toMap(vc)
		r.NoError(err)

		err = vc.AddLinkedDataProof(ldpContext)
		r.NoError(err)

		vcJSON, err := vc.MarshalJSON()
		r.NoError(err)

		vcMap, err := toMap(vcJSON)
		r.NoError(err)

		r.Contains(vcMap, "proof")
		vcProof := vcMap["proof"]
		vcProofMap, ok := vcProof.(map[string]interface{})
		r.True(ok)
		r.Contains(vcProofMap, "created")
		r.Contains(vcProofMap, "proofValue")
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

		err = vc.AddLinkedDataProof(ldpContext)
		r.Error(err)

		vc.CustomFields = nil
		ldpContextWithMissingSignatureType := &LinkedDataProofContext{
			Creator: "John",
			Suite:   ed25519signature2018.New(ed25519signature2018.WithSigner(getSigner(privKey))),
		}

		err = vc.AddLinkedDataProof(ldpContextWithMissingSignatureType)
		r.Error(err)
	})
}
