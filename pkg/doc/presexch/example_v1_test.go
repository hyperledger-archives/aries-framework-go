/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	. "github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
)

const dummy = "DUMMY"

func ExamplePresentationDefinition_CreateVP_v1() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{{
					Path:      []string{"$.age"},
					Predicate: &required,
					Filter: &Filter{
						Type:    &intFilterType,
						Minimum: 18,
					},
				}},
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
			Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: map[string]interface{}{
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
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
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
	//			"age": true,
	//			"credentialSubject": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func ExamplePresentationDefinition_CreateVP_v1_With_LDP_FormatAndProof() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{{
					Path:      []string{"$.age"},
					Predicate: &required,
					Filter: &Filter{
						Type:    &intFilterType,
						Minimum: 18,
					},
				}},
			},
		}},
		Format: &Format{
			Ldp: &LdpType{ProofType: []string{"JsonWebSignature2020"}},
		},
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
			Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			},
			Proofs: []verifiable.Proof{{"type": "JsonWebSignature2020"}},
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
	//				"format": "ldp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
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
	//			"age": true,
	//			"credentialSubject": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func ExamplePresentationDefinition_CreateVP_v1_With_LDPVC_FormatAndProof() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{{
					Path:      []string{"$.age"},
					Predicate: &required,
					Filter: &Filter{
						Type:    &intFilterType,
						Minimum: 18,
					},
				}},
			},
		}},
		Format: &Format{
			LdpVC: &LdpType{ProofType: []string{"JsonWebSignature2020"}},
		},
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
			Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"age":        21,
			},
			Proofs: []verifiable.Proof{{"type": "JsonWebSignature2020"}},
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
	//				"format": "ldp_vc",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
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
	//			"age": true,
	//			"credentialSubject": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func ExamplePresentationDefinition_CreateVP_multipleMatches() {
	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				Fields: []*Field{{
					Path: []string{"$.age"},
					Filter: &Filter{
						Type:    &intFilterType,
						Minimum: 18,
					},
				}},
			},
		}, {
			ID:      "first_name_descriptor",
			Purpose: "First name must be either Andrew or Jesse",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				Fields: []*Field{{
					Path: []string{"$.first_name"},
					Filter: &Filter{
						Type:    &strFilterType,
						Pattern: "Andrew|Jesse",
					},
				}},
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
				ID: "did:example:777",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:777",
			CustomFields: map[string]interface{}{
				"first_name": "Andrew",
				"last_name":  "Hanks",
				"age":        25,
			},
		},
		{
			ID:      "http://example.edu/credentials/888",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: verifiable.Issuer{
				ID: "did:example:888",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:888",
			CustomFields: map[string]interface{}{
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
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			},
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[1]"
	//				}
	//			},
	//			{
	//				"id": "first_name_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "first_name_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			},
	//			{
	//				"id": "first_name_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "first_name_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[1]"
	//				}
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
	//			"age": 25,
	//			"credentialSubject": "did:example:777",
	//			"first_name": "Andrew",
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:777",
	//			"last_name": "Hanks",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"age": 21,
	//			"credentialSubject": "did:example:888",
	//			"first_name": "Jesse",
	//			"id": "http://example.edu/credentials/888",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:888",
	//			"last_name": "Pinkman",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func ExamplePresentationDefinition_CreateVP_multipleMatchesDisclosure() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				Fields: []*Field{{
					Path: []string{"$.age"},
					Filter: &Filter{
						Type:    &intFilterType,
						Minimum: 18,
					},
				}},
			},
		}, {
			ID:      "first_name_descriptor",
			Purpose: "First name must be either Andrew or Jesse",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{{
					Path: []string{"$.first_name"},
					Filter: &Filter{
						Type:    &strFilterType,
						Pattern: "Andrew|Jesse",
					},
				}},
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
				ID: "did:example:777",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:777",
			CustomFields: map[string]interface{}{
				"first_name": "Andrew",
				"last_name":  "Hanks",
				"age":        25,
			},
		},
		{
			ID:      "http://example.edu/credentials/888",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: verifiable.Issuer{
				ID: "did:example:888",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:888",
			CustomFields: map[string]interface{}{
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
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			},
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[1]"
	//				}
	//			},
	//			{
	//				"id": "first_name_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "first_name_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[2]"
	//				}
	//			},
	//			{
	//				"id": "first_name_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "first_name_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[3]"
	//				}
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
	//			"age": 25,
	//			"credentialSubject": "did:example:777",
	//			"first_name": "Andrew",
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:777",
	//			"last_name": "Hanks",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"age": 21,
	//			"credentialSubject": "did:example:888",
	//			"first_name": "Jesse",
	//			"id": "http://example.edu/credentials/888",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:888",
	//			"last_name": "Pinkman",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": "did:example:777",
	//			"first_name": "Andrew",
	//			"id": "http://example.edu/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:777",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": "did:example:888",
	//			"first_name": "Jesse",
	//			"id": "http://example.edu/credentials/888",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:888",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func ExamplePresentationDefinition_CreateVP_submissionRequirementsLimitDisclosure() {
	required := Required

	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		SubmissionRequirements: []*SubmissionRequirement{
			{
				Rule: "all",
				From: "A",
			},
			{
				Rule:    "pick",
				Purpose: "We need your photo to identify you",
				Count:   1,
				FromNested: []*SubmissionRequirement{
					{
						Rule: "all",
						From: "drivers_license_image",
					},
					{
						Rule: "all",
						From: "passport_image",
					},
				},
			},
		},
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Group:   []string{"A"},
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				Fields: []*Field{{
					Path: []string{"$.age"},
					Filter: &Filter{
						Type:    &intFilterType,
						Minimum: 18,
					},
				}},
			},
		}, {
			ID:      "drivers_license_image_descriptor",
			Group:   []string{"drivers_license_image"},
			Purpose: "We need your photo to identify you",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{{
					Path: []string{"$.photo"},
					Filter: &Filter{
						Type:   &strFilterType,
						Format: "uri",
					},
				}},
			},
		}, {
			ID:      "passport_image_descriptor",
			Group:   []string{"passport_image"},
			Purpose: "We need your image to identify you",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				LimitDisclosure: &required,
				Fields: []*Field{{
					Path: []string{"$.image"},
					Filter: &Filter{
						Type:   &strFilterType,
						Format: "uri",
					},
				}},
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
				ID: "did:example:777",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:777",
			CustomFields: map[string]interface{}{
				"first_name": "Andrew",
				"last_name":  "Hanks",
				"image":      "http://image.com/user777",
				"age":        25,
			},
		},
		{
			ID:      "http://example.edu/credentials/888",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: verifiable.Issuer{
				ID: "did:example:888",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:888",
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"photo":      "http://image.com/user777",
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
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			},
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[1]"
	//				}
	//			},
	//			{
	//				"id": "drivers_license_image_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "drivers_license_image_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[2]"
	//				}
	//			},
	//			{
	//				"id": "passport_image_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "passport_image_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[3]"
	//				}
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
	//			"age": 25,
	//			"credentialSubject": "did:example:777",
	//			"first_name": "Andrew",
	//			"id": "http://example.edu/credentials/777",
	//			"image": "http://image.com/user777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:777",
	//			"last_name": "Hanks",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"age": 21,
	//			"credentialSubject": "did:example:888",
	//			"first_name": "Jesse",
	//			"id": "http://example.edu/credentials/888",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:888",
	//			"last_name": "Pinkman",
	//			"photo": "http://image.com/user777",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": "did:example:888",
	//			"id": "http://example.edu/credentials/888",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:888",
	//			"photo": "http://image.com/user777",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": "did:example:777",
	//			"id": "http://example.edu/credentials/777",
	//			"image": "http://image.com/user777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:777",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

func ExamplePresentationDefinition_CreateVP_submissionRequirements() {
	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		SubmissionRequirements: []*SubmissionRequirement{
			{
				Rule: "all",
				From: "A",
			},
			{
				Rule:    "pick",
				Purpose: "We need your photo to identify you.",
				Count:   1,
				FromNested: []*SubmissionRequirement{
					{
						Rule: "all",
						From: "drivers_license_image",
					},
					{
						Rule: "all",
						From: "passport_image",
					},
				},
			},
		},
		InputDescriptors: []*InputDescriptor{{
			ID:      "age_descriptor",
			Group:   []string{"A"},
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				Fields: []*Field{{
					Path: []string{"$.age"},
					Filter: &Filter{
						Type:    &intFilterType,
						Minimum: 18,
					},
				}},
			},
		}, {
			ID:      "drivers_license_image_descriptor",
			Group:   []string{"drivers_license_image"},
			Purpose: "We need your photo to identify you",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				Fields: []*Field{{
					Path: []string{"$.photo"},
					Filter: &Filter{
						Type:   &strFilterType,
						Format: "uri",
					},
				}},
			},
		}, {
			ID:      "passport_image_descriptor",
			Group:   []string{"passport_image"},
			Purpose: "We need your image to identify you",
			Schema: []*Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &Constraints{
				Fields: []*Field{{
					Path: []string{"$.image"},
					Filter: &Filter{
						Type:   &strFilterType,
						Format: "uri",
					},
				}},
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
				ID: "did:example:777",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:777",
			CustomFields: map[string]interface{}{
				"first_name": "Andrew",
				"last_name":  "Hanks",
				"image":      "http://image.com/user777",
				"age":        25,
			},
		},
		{
			ID:      "http://example.edu/credentials/888",
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Types:   []string{"VerifiableCredential"},
			Issuer: verifiable.Issuer{
				ID: "did:example:888",
			},
			Issued: &util.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:888",
			CustomFields: map[string]interface{}{
				"first_name": "Jesse",
				"last_name":  "Pinkman",
				"photo":      "http://image.com/user777",
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
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			},
	//			{
	//				"id": "age_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "age_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[1]"
	//				}
	//			},
	//			{
	//				"id": "drivers_license_image_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "drivers_license_image_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[1]"
	//				}
	//			},
	//			{
	//				"id": "passport_image_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "passport_image_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
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
	//			"age": 25,
	//			"credentialSubject": "did:example:777",
	//			"first_name": "Andrew",
	//			"id": "http://example.edu/credentials/777",
	//			"image": "http://image.com/user777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:777",
	//			"last_name": "Hanks",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"age": 21,
	//			"credentialSubject": "did:example:888",
	//			"first_name": "Jesse",
	//			"id": "http://example.edu/credentials/888",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:888",
	//			"last_name": "Pinkman",
	//			"photo": "http://image.com/user777",
	//			"type": "VerifiableCredential"
	//		}
	//	]
	//}
}

// Example of a Verifier verifying the presentation submission of a Holder.
func ExamplePresentationDefinition_Match() {
	// verifier sends their presentation definitions to the holder
	verifierDefinitions := &PresentationDefinition{
		InputDescriptors: []*InputDescriptor{
			{
				ID: "banking",
				Schema: []*Schema{{
					URI: "https://example.org/examples#Customer",
				}},
			},
			{
				ID: "residence",
				Schema: []*Schema{{
					URI: "https://example.org/examples#Street",
				}},
			},
		},
	}

	// holder fetches their credentials
	accountCredential := fetchVC([]string{"https://example.context.jsonld/account"}, []string{"Customer"})
	addressCredential := fetchVC([]string{"https://example.context.jsonld/address"}, []string{"Street"})

	// holder builds their presentation submission against the verifier's definitions
	vp, err := newPresentationSubmission(
		&PresentationSubmission{DescriptorMap: []*InputDescriptorMapping{
			{
				ID:   "banking",
				Path: "$.verifiableCredential[0]",
			},
			{
				ID:   "residence",
				Path: "$.verifiableCredential[1]",
			},
		}},
		accountCredential, addressCredential,
	)
	if err != nil {
		panic(err)
	}

	// holder sends VP over the wire to the verifier
	vpBytes, err := json.Marshal(vp)
	if err != nil {
		panic(err)
	}

	// load json-ld context
	loader, err := ldtestutil.DocumentLoader(
		ldcontext.Document{
			URL:     "https://example.context.jsonld/account",
			Content: []byte(exampleJSONLDContext),
		},
		ldcontext.Document{
			URL:     "https://example.context.jsonld/address",
			Content: []byte(exampleJSONLDContext),
		},
	)
	if err != nil {
		panic(err)
	}

	// verifier parses the vp
	// note: parsing this VP without verifying the proof just for example purposes.
	//       Always verify proofs in production!
	receivedVP, err := verifiable.ParsePresentation(vpBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	if err != nil {
		panic(err)
	}

	// verifier matches the received VP against their definitions
	matched, err := verifierDefinitions.Match(
		receivedVP, loader,
		WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)),
	)
	if err != nil {
		panic(fmt.Errorf("presentation submission did not match definitions: %w", err))
	}

	for _, descriptor := range verifierDefinitions.InputDescriptors {
		receivedCred := matched[descriptor.ID]
		fmt.Printf(
			"verifier received the '%s' credential for the input descriptor id '%s'\n",
			receivedCred.Context[1], descriptor.ID)
	}

	// Output:
	// verifier received the 'https://example.context.jsonld/account' credential for the input descriptor id 'banking'
	// verifier received the 'https://example.context.jsonld/address' credential for the input descriptor id 'residence'
}

func newPresentationSubmission(
	submission *PresentationSubmission, vcs ...*verifiable.Credential) (*verifiable.Presentation, error) {
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vcs...))
	if err != nil {
		return nil, err
	}

	vp.Context = append(vp.Context, "https://identity.foundation/presentation-exchange/submission/v1")
	vp.Type = append(vp.Type, "PresentationSubmission")

	if submission != nil {
		vp.CustomFields = make(map[string]interface{})
		vp.CustomFields["presentation_submission"] = toExampleMap(submission)
	}

	return vp, nil
}

func toExampleMap(v interface{}) map[string]interface{} {
	bits, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	m := make(map[string]interface{})

	err = json.Unmarshal(bits, &m)
	if err != nil {
		panic(err)
	}

	return m
}

const exampleJSONLDContext = `{
    "@context":{
      "@version":1.1,
      "@protected":true,
      "name":"http://schema.org/name",
      "ex":"https://example.org/examples#",
	  "Customer":"ex:Customer",
	  "Street":"ex:Street",
      "xsd":"http://www.w3.org/2001/XMLSchema#"
   }
}`

func fetchVC(ctx, types []string) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context: append([]string{verifiable.ContextURI}, ctx...),
		Types:   append([]string{verifiable.VCType}, types...),
		ID:      "http://test.credential.com/123",
		Issuer:  verifiable.Issuer{ID: "http://test.issuer.com"},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": uuid.New().String(),
		},
	}

	return vc
}
