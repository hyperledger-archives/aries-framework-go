/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020_test

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/bbsblssignatureproof2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

//nolint:gochecknoglobals
var (
	//go:embed testdata/case16_vc.jsonld
	case16VC string // Case 16 (https://github.com/w3c-ccg/vc-http-api/pull/128)
	//go:embed testdata/case16_reveal_doc.jsonld
	case16RevealDoc string
	//go:embed testdata/case18_vc.jsonld
	case18VC string // Case 18 (https://github.com/w3c-ccg/vc-http-api/pull/128)
	//go:embed testdata/case18_reveal_doc.jsonld
	case18RevealDoc string
	//go:embed testdata/doc_with_many_proofs.jsonld
	docWithManyProofsJSON string //nolint:unused // re-enable test that uses this var (#2562)
)

// nolint
func TestSuite_SelectiveDisclosure(t *testing.T) {
	// pkBase58 from did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2
	pkBase58 := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
	pubKeyBytes := base58.Decode(pkBase58)

	nonce, err := base64.StdEncoding.DecodeString("G/hn9Ca9bIWZpJGlhnr/41r8RB0OO0TLChZASr3QJVztdri/JzS8Zf/xWJT5jW78zlM=")
	require.NoError(t, err)

	docMap := toMap(t, case16VC)
	revealDocMap := toMap(t, case16RevealDoc)

	s := bbsblssignatureproof2020.New()

	const proofField = "proof"

	pubKeyResolver := &testKeyResolver{
		publicKey: &verifier.PublicKey{
			Type:  "Bls12381G2Key2020",
			Value: pubKeyBytes,
		},
	}

	t.Run("single BBS+ signature", func(t *testing.T) {
		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMap, revealDocMap, nonce,
			pubKeyResolver, testutil.WithDocumentLoader(t))
		require.NoError(t, err)
		require.NotEmpty(t, docWithSelectiveDisclosure)
		require.Contains(t, docWithSelectiveDisclosure, proofField)

		proofs, ok := docWithSelectiveDisclosure[proofField].([]map[string]interface{})
		require.True(t, ok)

		require.Len(t, proofs, 1)
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[0]["type"])
		require.NotEmpty(t, proofs[0]["proofValue"])
	})

	t.Run("several proofs including BBS+ signature", func(t *testing.T) {
		// TODO re-enable (#2562).
		t.Skip()
		docWithSeveralProofsMap := toMap(t, docWithManyProofsJSON)

		pubKeyBytes2 := base58.Decode("tPTWWeUm8yT3aR9HtMvo2pLLvAdyV9Z4nJYZ2ZsyoLVpTupVb7NaRJ3tZePF6YsCN1nw7McqJ38tvpmQxKQxrTbyzjiewUDaj5jbD8gVfpfXJL2SfPBw4TGjYPA6zg6Jrxn")

		compositeResolver := &testKeyResolver{
			variants: map[string]*verifier.PublicKey{
				"did:example:489398593#test": {
					Type:  "Bls12381G2Key2020",
					Value: pubKeyBytes},
				"did:example:123456#key2": {
					Type:  "Bls12381G2Key2020",
					Value: pubKeyBytes2},
			},
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docWithSeveralProofsMap, revealDocMap, nonce,
			compositeResolver, testutil.WithDocumentLoader(t))
		require.NoError(t, err)
		require.NotEmpty(t, docWithSelectiveDisclosure)
		require.Contains(t, docWithSelectiveDisclosure, proofField)

		proofs, ok := docWithSelectiveDisclosure[proofField].([]map[string]interface{})
		require.True(t, ok)

		require.Len(t, proofs, 2)
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[0]["type"])
		require.NotEmpty(t, proofs[0]["proofValue"])
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[1]["type"])
		require.NotEmpty(t, proofs[1]["proofValue"])
	})

	t.Run("malformed input", func(t *testing.T) {
		docMap := make(map[string]interface{})
		docMap["@context"] = "http://localhost/nocontext"
		docMap["bad"] = "example"
		docMap["proof"] = "example"

		_, err := s.SelectiveDisclosure(docMap, revealDocMap, nonce, pubKeyResolver, testutil.WithDocumentLoader(t))
		require.Error(t, err)
	})

	t.Run("no proof", func(t *testing.T) {
		docMapWithoutProof := make(map[string]interface{}, len(docMap)-1)

		for k, v := range docMap {
			if k != proofField {
				docMapWithoutProof[k] = v
			}
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMapWithoutProof, revealDocMap, nonce,
			pubKeyResolver, testutil.WithDocumentLoader(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "document does not have a proof")
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("invalid proof", func(t *testing.T) {
		docMapWithInvalidProof := make(map[string]interface{}, len(docMap)-1)

		for k, v := range docMap {
			if k != proofField {
				docMapWithInvalidProof[k] = v
			} else {
				docMapWithInvalidProof[k] = "invalid proof"
			}
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMapWithInvalidProof, revealDocMap, nonce,
			pubKeyResolver, testutil.WithDocumentLoader(t))
		require.Error(t, err)
		require.EqualError(t, err, "get BLS proofs: read document proofs: proof is not map or array of maps")
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("invalid proof value", func(t *testing.T) {
		docMapWithInvalidProofValue := make(map[string]interface{}, len(docMap))

		for k, v := range docMap {
			if k == proofField {
				proofMap := make(map[string]interface{})

				for k1, v1 := range v.(map[string]interface{}) {
					if k1 == "proofValue" {
						proofMap[k1] = "invalid"
					} else {
						proofMap[k1] = v1
					}
				}

				docMapWithInvalidProofValue[proofField] = proofMap
			} else {
				docMapWithInvalidProofValue[k] = v
			}
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMapWithInvalidProofValue, revealDocMap, nonce,
			pubKeyResolver, testutil.WithDocumentLoader(t))
		require.Error(t, err)
		require.EqualError(t, err, "generate signature proof: derive BBS+ proof: parse signature: invalid size of signature") //nolint:lll
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("invalid input BBS+ proof value", func(t *testing.T) {
		docMapWithInvalidProofType := make(map[string]interface{}, len(docMap)-1)

		for k, v := range docMap {
			if k == proofField {
				proofMap := make(map[string]interface{})

				for k1, v1 := range v.(map[string]interface{}) {
					if k1 == "type" {
						proofMap[k1] = "invalid"
					} else {
						proofMap[k1] = v1
					}
				}

				docMapWithInvalidProofType[proofField] = proofMap
			} else {
				docMapWithInvalidProofType[k] = v
			}
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMapWithInvalidProofType, revealDocMap, nonce,
			pubKeyResolver, testutil.WithDocumentLoader(t))
		require.Error(t, err)
		require.EqualError(t, err, "no BbsBlsSignature2020 proof present")
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("failed to resolve public key", func(t *testing.T) {
		failingPublicKeyResolver := &testKeyResolver{
			err: errors.New("public key not found"),
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMap, revealDocMap, nonce,
			failingPublicKeyResolver, testutil.WithDocumentLoader(t))
		require.Error(t, err)
		require.EqualError(t, err, "generate signature proof: get public key and signature: resolve public key of BBS+ signature: public key not found") //nolint:lll
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("Case 18 derives into Case 19", func(t *testing.T) {
		case18DocMap := toMap(t, case18VC)
		case18RevealDocMap := toMap(t, case18RevealDoc)

		case19Nonce, err := base64.StdEncoding.DecodeString("lEixQKDQvRecCifKl789TQj+Ii6YWDLSwn3AxR0VpPJ1QV5htod/0VCchVf1zVM0y2E=")
		require.NoError(t, err)

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(case18DocMap, case18RevealDocMap, case19Nonce,
			pubKeyResolver, testutil.WithDocumentLoader(t))
		require.NoError(t, err)
		require.NotEmpty(t, docWithSelectiveDisclosure)
		require.Contains(t, docWithSelectiveDisclosure, proofField)

		proofs, ok := docWithSelectiveDisclosure[proofField].([]map[string]interface{})
		require.True(t, ok)

		require.Len(t, proofs, 1)
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[0]["type"])
		require.NotEmpty(t, proofs[0]["proofValue"])

		case18DerivationBytes, err := json.Marshal(docWithSelectiveDisclosure)

		pubKeyFetcher := verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")

		loader, err := testutil.DocumentLoader()
		require.NoError(t, err)

		_, err = verifiable.ParseCredential(case18DerivationBytes, verifiable.WithPublicKeyFetcher(pubKeyFetcher),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
	})
}

func toMap(t *testing.T, doc string) map[string]interface{} {
	var docMap map[string]interface{}
	err := json.Unmarshal([]byte(doc), &docMap)
	require.NoError(t, err)

	return docMap
}

type testKeyResolver struct {
	publicKey *verifier.PublicKey
	variants  map[string]*verifier.PublicKey
	err       error
}

func (r *testKeyResolver) Resolve(id string) (*verifier.PublicKey, error) {
	if r.err != nil {
		return nil, r.err
	}

	if len(r.variants) > 0 {
		return r.variants[id], nil
	}

	return r.publicKey, r.err
}
