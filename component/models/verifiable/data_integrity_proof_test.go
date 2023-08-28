/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite/ecdsa2019"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

func Test_DataIntegrity_SignVerify(t *testing.T) {
	vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
	"https://w3id.org/security/data-integrity/v1"
  ],
  "id": "https://example.com/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "issuer": "did:key:z6Mkj7of2aaooXhTJvJ5oCL9ZVcAS472ZBuSjYyXDa4bWT32",
  "issuanceDate": "2020-01-17T15:14:09.724Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  }
}
`

	kms, err := createKMS()
	require.NoError(t, err)

	cr, err := tinkcrypto.New()
	require.NoError(t, err)

	docLoader := createTestDocumentLoader(t)

	_, keyBytes, err := kms.CreateAndExportPubKeyBytes(kmsapi.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	key, err := jwkkid.BuildJWK(keyBytes, kmsapi.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	const signingDID = "did:foo:bar"

	const vmID = "#key-1"

	vm, err := did.NewVerificationMethodFromJWK(signingDID+vmID, "JsonWebKey2020", signingDID, key)
	require.NoError(t, err)

	resolver := resolveFunc(func(id string) (*did.DocResolution, error) {
		return makeMockDIDResolution(signingDID, vm, did.AssertionMethod), nil
	})

	signerSuite := ecdsa2019.NewSignerInitializer(&ecdsa2019.SignerInitializerOptions{
		SignerGetter:     ecdsa2019.WithLocalKMSSigner(kms, cr),
		LDDocumentLoader: docLoader,
	})

	signer, err := dataintegrity.NewSigner(&dataintegrity.Options{
		DIDResolver: resolver,
	}, signerSuite)
	require.NoError(t, err)

	signContext := &DataIntegrityProofContext{
		SigningKeyID: signingDID + vmID,
		ProofPurpose: "",
		CryptoSuite:  ecdsa2019.SuiteType,
		Created:      nil,
		Domain:       "mock-domain",
		Challenge:    "mock-challenge",
	}

	verifySuite := ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: docLoader,
	})

	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: resolver,
	}, verifySuite)
	require.NoError(t, err)

	t.Run("credential", func(t *testing.T) {
		vc, e := parseTestCredential(t, []byte(vcJSON), WithDisabledProofCheck(), WithStrictValidation())
		require.NoError(t, e)

		e = vc.AddDataIntegrityProof(signContext, signer)
		require.NoError(t, e)

		vcBytes, e := vc.MarshalJSON()
		require.NoError(t, e)

		_, e = parseTestCredential(t, vcBytes, WithDataIntegrityVerifier(verifier), WithStrictValidation())
		require.NoError(t, e)

		t.Run("fail if not provided verifier", func(t *testing.T) {
			_, e = parseTestCredential(t, vcBytes, WithDataIntegrityVerifier(nil))
			require.Error(t, e)
			require.Contains(t, e.Error(), "needs data integrity verifier")
		})
	})

	t.Run("presentation", func(t *testing.T) {
		vp, e := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
		require.NoError(t, e)

		e = vp.AddDataIntegrityProof(signContext, signer)
		require.NoError(t, e)

		vpBytes, e := vp.MarshalJSON()
		require.NoError(t, e)

		_, e = newTestPresentation(t, vpBytes,
			WithPresDataIntegrityVerifier(verifier),
			WithPresExpectedDataIntegrityFields(assertionMethod, "mock-domain", "mock-challenge"),
		)
		require.NoError(t, e)

		t.Run("fail if not provided verifier", func(t *testing.T) {
			_, e = parseTestCredential(t, vpBytes)
			require.Error(t, e)
			require.Contains(t, e.Error(), "needs data integrity verifier")
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("marshal json", func(t *testing.T) {
			vc := &Credential{
				CustomContext: []interface{}{make(chan int)},
			}

			err := vc.AddDataIntegrityProof(&DataIntegrityProofContext{}, &dataintegrity.Signer{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "add data integrity proof to VC")

			vp := &Presentation{
				Proofs: []Proof{
					{
						"foo": make(chan int),
					},
				},
			}

			err = vp.AddDataIntegrityProof(&DataIntegrityProofContext{}, &dataintegrity.Signer{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "add data integrity proof to VP")
		})

		t.Run("add data integrity proof", func(t *testing.T) {
			vc := &Credential{}

			err := vc.AddDataIntegrityProof(&DataIntegrityProofContext{}, &dataintegrity.Signer{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported cryptographic suite")

			vp := &Presentation{}

			err = vp.AddDataIntegrityProof(&DataIntegrityProofContext{
				Created: &time.Time{},
			}, &dataintegrity.Signer{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported cryptographic suite")
		})
	})
}

type resolveFunc func(id string) (*did.DocResolution, error)

func (f resolveFunc) Resolve(id string, opts ...vdrspi.DIDMethodOption) (*did.DocResolution, error) {
	return f(id)
}

func makeMockDIDResolution(id string, vm *did.VerificationMethod, vr did.VerificationRelationship) *did.DocResolution {
	ver := []did.Verification{{
		VerificationMethod: *vm,
		Relationship:       vr,
	}}

	doc := &did.Doc{
		ID: id,
	}

	switch vr {
	case did.VerificationRelationshipGeneral:
		doc.VerificationMethod = []did.VerificationMethod{*vm}
	case did.Authentication:
		doc.Authentication = ver
	case did.AssertionMethod:
		doc.AssertionMethod = ver
	}

	return &did.DocResolution{
		DIDDocument: doc,
	}
}
