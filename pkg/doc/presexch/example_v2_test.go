/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	. "github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	jsonutil "github.com/hyperledger/aries-framework-go/pkg/doc/util/json"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
)

func ExamplePresentationDefinition_CreateVP_v2() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP([]*verifiable.Credential{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			},
		},
	}, loader, verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		panic(err)
	}

	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	//{
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$.verifiableCredential[0]"
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"age": true,
	//				"first_name": "Jesse",
	//				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	//				"last_name": "Pinkman"
	//			},
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func ExamplePresentationDefinition_CreateVP_withFormat() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		Format: &Format{
			LdpVP: &LdpType{
				ProofType: []string{"Ed25519Signature2018"},
			},
		},
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP([]*verifiable.Credential{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			},
			Proofs: []verifiable.Proof{
				{"type": "Ed25519Signature2018"},
			},
		},
	}, loader, verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		panic(err)
	}

	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	//{
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$.verifiableCredential[0]"
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"age": true,
	//				"first_name": "Jesse",
	//				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	//				"last_name": "Pinkman"
	//			},
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func ExamplePresentationDefinition_CreateVP_withFormatInInputDescriptor() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Format: &Format{
				LdpVP: &LdpType{
					ProofType: []string{"Ed25519Signature2018"},
				},
			},
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP([]*verifiable.Credential{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			},
			Proofs: []verifiable.Proof{
				{"type": "Ed25519Signature2018"},
			},
		},
	}, loader, verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		panic(err)
	}

	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	//{
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$.verifiableCredential[0]"
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"age": true,
	//				"first_name": "Jesse",
	//				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	//				"last_name": "Pinkman"
	//			},
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func TestExamplePresentationDefinition_CreateVPWithFormat_NoMatch(t *testing.T) {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		Format: &Format{
			LdpVP: &LdpType{
				ProofType: []string{"Ed25519Signature2018"},
			},
		},
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.age", "$.vc.credentialSubject.age", "$.age"},
						Predicate: &required,
						Filter: &Filter{
							Type:    &intFilterType,
							Minimum: 18,
						},
					},
					{
						Path: []string{"$.credentialSchema[0].id", "$.credentialSchema.id", "$.vc.credentialSchema.id"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "hub://did:foo:123/Collections/schema.us.gov/passport.json",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	_, err = pd.CreateVP([]*verifiable.Credential{
		{
			ID:      "http://example.edu/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Schemas: []verifiable.TypedID{{
				ID:   "hub://did:foo:123/Collections/schema.us.gov/passport.json",
				Type: "JsonSchemaValidator2018",
			}},

			Subject: map[string]interface{}{
				"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			},
			Proofs: []verifiable.Proof{
				{"type": "JsonWebSignature2020"},
			},
		},
	}, loader, verifiable.WithJSONLDDocumentLoader(loader))

	require.EqualError(t, err, "credentials do not satisfy requirements")
}

func ExamplePresentationDefinition_CreateVP_withFrame() {
	vcJSON := `
	{
	 "@context": [
	   "https://www.w3.org/2018/credentials/v1",
	   "https://w3id.org/citizenship/v1",
	   "https://w3id.org/security/bbs/v1"
	 ],
	 "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	 "type": [
	   "VerifiableCredential",
	   "PermanentResidentCard"
	 ],
	 "issuer": "did:example:489398593",
	 "identifier": "83627465",
	 "name": "Permanent Resident Card",
	 "description": "Government of Example Permanent Resident Card.",
	 "issuanceDate": "2019-12-03T12:19:52Z",
	 "expirationDate": "2029-12-03T12:19:52Z",
	 "credentialSubject": {
	   "id": "did:example:b34ca6cd37bbf23",
	   "type": [
	     "PermanentResident",
	     "Person"
	   ],
	   "givenName": "JOHN",
	   "familyName": "SMITH",
	   "gender": "Male",
	   "image": "data:image/png;base64,iVBORw0KGgokJggg==",
	   "residentSince": "2015-01-01",
	   "lprCategory": "C09",
	   "lprNumber": "999-999-999",
	   "commuterClassification": "C1",
	   "birthCountry": "Bahamas",
	   "birthDate": "1958-07-17"
	 }
	}
	`

	frameJSONWithMissingIssuer := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "@explicit": true,
  "identifier": {},
  "issuer": {},
  "issuanceDate": {},
  "credentialSubject": {
    "@explicit": true,
    "type": ["PermanentResident", "Person"],
    "givenName": {},
    "familyName": {},
    "gender": {},
	"birthCountry": {}
  }
}
`

	frameDoc, err := jsonutil.ToMap(frameJSONWithMissingIssuer)
	if err != nil {
		panic(err)
	}

	required := Required

	pd := &PresentationDefinition{
		ID:    "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Frame: frameDoc,
		InputDescriptors: []*InputDescriptor{{
			ID: "country_descriptor",
			Constraints: &Constraints{
				Fields: []*Field{
					{
						Path:      []string{"$.credentialSubject.birthCountry", "$.vc.credentialSubject.birthCountry"},
						Predicate: &required,
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "Bahamas",
						},
					},
				},
			},
		}},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vc, err := verifiable.ParseCredential([]byte(vcJSON), verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		panic(err)
	}

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	if err != nil {
		panic(err)
	}

	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		panic(err)
	}

	signVCWithBBS(privKey, vc, loader)

	vp, err := pd.CreateVP([]*verifiable.Credential{vc}, loader, verifiable.WithJSONLDDocumentLoader(loader), verifiable.WithPublicKeyFetcher(
		verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")))
	if err != nil {
		panic(err)
	}

	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy
	vp.Credentials()[0].(*verifiable.Credential).Proofs[0]["created"] = dummy
	vp.Credentials()[0].(*verifiable.Credential).Proofs[0]["proofValue"] = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	//{
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "country_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$.verifiableCredential[0]"
	//			}
	//		]
	//	},
	//	"type": [
	//		"VerifiablePresentation",
	//		"PresentationSubmission"
	//	],
	//	"verifiableCredential": [
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1",
	//				"https://w3id.org/citizenship/v1",
	//				"https://w3id.org/security/bbs/v1"
	//			],
	//			"credentialSubject": {
	//				"birthCountry": true,
	//				"familyName": "SMITH",
	//				"gender": "Male",
	//				"givenName": "JOHN",
	//				"id": "did:example:b34ca6cd37bbf23",
	//				"type": [
	//					"Person",
	//					"PermanentResident"
	//				]
	//			},
	//			"id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	//			"identifier": "83627465",
	//			"issuanceDate": "2019-12-03T12:19:52Z",
	//			"issuer": "did:example:489398593",
	//			"proof": {
	//				"created": "DUMMY",
	//				"nonce": "",
	//				"proofPurpose": "assertionMethod",
	//				"proofValue": "DUMMY",
	//				"type": "BbsBlsSignatureProof2020",
	//				"verificationMethod": "did:example:123456#key1"
	//			},
	//			"type": [
	//				"PermanentResidentCard",
	//				"VerifiableCredential"
	//			]
	//		}
	//	]
	//}
}

func signVCWithBBS(privKey *bbs12381g2pub.PrivateKey, vc *verifiable.Credential, documentLoader ld.DocumentLoader) {
	bbsSigner, err := newBBSSigner(privKey)
	if err != nil {
		panic(err)
	}

	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(bbsSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:example:123456#key1",
	}

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(documentLoader))
	if err != nil {
		panic(err)
	}
}
