/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	ldprocessor "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ed25519signature2018"
	jsonutil "github.com/hyperledger/aries-framework-go/component/models/util/json"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestParsePresentationFromLinkedDataProof(t *testing.T) {
	r := require.New(t)

	signer, err := newCryptoSigner(kms.ED25519Type)
	r.NoError(err)

	ss := ed25519signature2018.New(suite.WithSigner(signer),
		suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())) // todo use crypto verifier

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: SignatureJWS,
		Suite:                   ss,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, err := newTestPresentation(t, []byte(validPresentation))
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	vcWithLdp, err := newTestPresentation(t, vcBytes,
		WithPresEmbeddedSignatureSuites(ss),
		WithPresPublicKeyFetcher(SingleKey(signer.PublicKeyBytes(), kms.ED25519)))
	r.NoError(err)

	r.NoError(err)
	r.Equal(vc, vcWithLdp)

	// signature suite is not passed, cannot make a proof check
	vcWithLdp, err = newTestPresentation(t, vcBytes)
	r.Error(err)
	require.Nil(t, vcWithLdp)
}

func TestPresentation_AddLinkedDataProof(t *testing.T) {
	r := require.New(t)

	signer, err := newCryptoSigner(kms.ED25519Type)
	r.NoError(err)

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: SignatureProofValue,
		Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
	}

	t.Run("Add a valid Linked Data proof to VC", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation))
		r.NoError(err)

		err = vp.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
		r.NoError(err)

		err = vp.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
		r.NoError(err)

		vpJSON, err := vp.MarshalJSON()
		r.NoError(err)

		vpMap, err := jsonutil.ToMap(vpJSON)
		r.NoError(err)

		r.Contains(vpMap, "proof")
		vpProof := vpMap["proof"]
		vpProofs, ok := vpProof.([]interface{})
		r.True(ok)
		r.Len(vpProofs, 2)
		newVPProof, ok := vpProofs[1].(map[string]interface{})
		r.True(ok)
		r.Contains(newVPProof, "created")
		r.Contains(newVPProof, "proofValue")
		r.Equal("Ed25519Signature2018", newVPProof["type"])
	})
}
