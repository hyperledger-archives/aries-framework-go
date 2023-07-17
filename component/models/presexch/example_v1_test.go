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

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	ldtestutil "github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	. "github.com/hyperledger/aries-framework-go/component/models/presexch"
	utiltime "github.com/hyperledger/aries-framework-go/component/models/util/time"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
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
			Issued: &utiltime.TimeWrapper{
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

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
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
	// }
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
			Issued: &utiltime.TimeWrapper{
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

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
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
	// }
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
			Issued: &utiltime.TimeWrapper{
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

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
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
	// }
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
			Issued: &utiltime.TimeWrapper{
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
			Issued: &utiltime.TimeWrapper{
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

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
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
	// }
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
			Issued: &utiltime.TimeWrapper{
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
			Issued: &utiltime.TimeWrapper{
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

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
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
	// }
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
			Issued: &utiltime.TimeWrapper{
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
			Issued: &utiltime.TimeWrapper{
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

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
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
	//		}
	//	]
	// }
}

func ExamplePresentationDefinition_CreateVP_submissionRequirements() {
	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		SubmissionRequirements: []*SubmissionRequirement{
			// {
			// 	Rule: "all",
			// 	FromNested: []*SubmissionRequirement{
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
			// 	},
			// },
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
			Issued: &utiltime.TimeWrapper{
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
			Issued: &utiltime.TimeWrapper{
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

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
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
	// }
}

func ExamplePresentationDefinition_CreateVP_submissionRequirements2() {
	// TODO: this example demonstrates a bug, need to investigate
	//  - create a unit test that simplifies this for investigation
	//  - describe the issue for Rolson
	pd := &PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "The following accreditations and clearances are required to proceed with your application.",
		SubmissionRequirements: []*SubmissionRequirement{
			{
				Rule:    "pick",
				Purpose: "We need a photo from government ID for your badge.",
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
			{
				Rule:    "all",
				Purpose: "We need to validate your flight experience.",
				FromNested: []*SubmissionRequirement{
					{
						Rule:  "pick",
						Count: 1,
						From:  "flight_training",
					},
					{
						Rule: "pick",
						Min:  1,
						From: "pilot_employment",
					},
				},
			},
		},
		InputDescriptors: []*InputDescriptor{
			{
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
			},
			{
				ID:      "passport_image_descriptor",
				Group:   []string{"passport_image"},
				Purpose: "We need your photo to identify you",
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
			},
			{
				ID:    "flight_training_1",
				Group: []string{"flight_training"},
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.credentialSubject.pilot_id"},
						Filter: &Filter{
							Type: &strFilterType,
						},
					}, {
						Path: []string{"$.credentialSubject.expiry"},
						Filter: &Filter{
							Type: &strFilterType,
						},
					}},
				},
			},
			{
				ID:    "employment_private_1",
				Group: []string{"pilot_employment"},
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.credentialSubject.pilot_id"},
						Filter: &Filter{
							Type: &strFilterType,
						},
					}, {
						Path: []string{"$.credentialSubject.employed_since"},
						Filter: &Filter{
							Type: &strFilterType,
						},
					}},
				},
			},
			{
				ID:    "employment_gov",
				Group: []string{"pilot_employment"},
				Schema: []*Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &Constraints{
					Fields: []*Field{{
						Path: []string{"$.credentialSubject.clearance_level"},
						Filter: &Filter{
							Type: &arrFilterType,
						},
					}, {
						Path: []string{"$.credentialSubject.travel_authorization.subnational"},
						Filter: &Filter{
							Type:  &strFilterType,
							Const: "Allow",
						},
					}},
				},
			},
		},
	}

	loader, err := ldtestutil.DocumentLoader()
	if err != nil {
		panic(err)
	}

	vp, err := pd.CreateVP([]*verifiable.Credential{
		{
			ID:      "http://example.dmv/credentials/777",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Issuer: verifiable.Issuer{
				ID: "did:example:777",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Subject: "did:example:777",
			CustomFields: map[string]interface{}{
				"first_name": "Andrew",
				"last_name":  "Hanks",
				"photo":      "https://image.com/user777",
				"DOB":        "5/18/86",
			},
		},
		{
			ID:      "https://example.gov/credentials/888",
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Types:   []string{"VerifiableCredential", "GovSecureEmployeeCredential"},
			Issuer: verifiable.Issuer{
				ID: "did:example:888",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Subject: &verifiable.Subject{
				ID: "did:example:888",
				CustomFields: map[string]interface{}{
					"clearance_level": []string{"Public", "Low-Security", "Facility-Supervised"},
					"employee_id":     "2956348576547",
					"travel_authorization": map[string]interface{}{
						"subnational":           "Allow",
						"international_default": "S2-Signoff",
					},
				},
			},
		},
		{
			ID:      "https://example.faa/credentials/123",
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Types:   []string{"VerifiableCredential", "FlightCertificationCredential"},
			Issuer: verifiable.Issuer{
				ID: "did:example:123",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Subject: &verifiable.Subject{
				ID: "did:example:123",
				CustomFields: map[string]interface{}{
					"pilot_id":                "4358793",
					"accrediting_institution": "Nowheresville Community College",
					"licensed_vehicles":       []string{"hang_glider", "kite", "Cessna 152"},
					"expiry":                  "2027-12-30",
				},
			},
		},
		{
			ID:      "https://example.business/credentials/employee/12345",
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Types:   []string{"VerifiableCredential", "EmployeeCredential"},
			Issuer: verifiable.Issuer{
				ID: "did:example:12345",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Subject: &verifiable.Subject{
				ID: "did:example:12345",
				CustomFields: map[string]interface{}{
					"employed_since": "2021-07-06",
					"employed_until": "2021-07-07",
					"role":           "Management Consultant",
					"reference":      "did:example:10101",
					"pilot_id":       "4358793",
				},
			},
		},
		{
			ID:      "https://example.co.website/credentials/employee/7",
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Types:   []string{"VerifiableCredential", "EmployeeCredential"},
			Issuer: verifiable.Issuer{
				ID: "did:example:7",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Time{},
			},
			Subject: &verifiable.Subject{
				ID: "did:example:7",
				CustomFields: map[string]interface{}{
					"employed_since": "2017-01-01",
					"employed_until": "2021-08-09",
					"role":           "Customer Relationships Manager",
					"employer":       "Chucky Pilot's Bar & Grill",
					"pilot_points":   172,
					"pilot_id":       "Bravo-7",
				},
			},
		},
	}, loader, verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		panic(err)
	}

	vp.ID = dummy
	vp.CustomFields["presentation_submission"].(*PresentationSubmission).ID = dummy

	vpBytes, err := json.MarshalIndent(vp, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(vpBytes))
	// Output:
	// {
	//	"@context": [
	//		"https://www.w3.org/2018/credentials/v1",
	//		"https://identity.foundation/presentation-exchange/submission/v1"
	//	],
	//	"id": "DUMMY",
	//	"presentation_submission": {
	//		"id": "DUMMY",
	//		"definition_id": "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
	//		"descriptor_map": [
	//			{
	//				"id": "drivers_license_image_descriptor",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "drivers_license_image_descriptor",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[0]"
	//				}
	//			},
	//			{
	//				"id": "employment_private_1",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "employment_private_1",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[1]"
	//				}
	//			},
	//			{
	//				"id": "employment_private_1",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "employment_private_1",
	//					"format": "ldp_vc",
	//					"path": "$.verifiableCredential[2]"
	//				}
	//			},
	//			{
	//				"id": "flight_training_1",
	//				"format": "ldp_vp",
	//				"path": "$",
	//				"path_nested": {
	//					"id": "flight_training_1",
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
	//			"DOB": "5/18/86",
	//			"credentialSubject": "did:example:777",
	//			"first_name": "Andrew",
	//			"id": "http://example.dmv/credentials/777",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:777",
	//			"last_name": "Hanks",
	//			"photo": "https://image.com/user777",
	//			"type": "VerifiableCredential"
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"employed_since": "2021-07-06",
	//				"employed_until": "2021-07-07",
	//				"id": "did:example:12345",
	//				"pilot_id": "4358793",
	//				"reference": "did:example:10101",
	//				"role": "Management Consultant"
	//			},
	//			"id": "https://example.business/credentials/employee/12345",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:12345",
	//			"type": [
	//				"VerifiableCredential",
	//				"EmployeeCredential"
	//			]
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"employed_since": "2017-01-01",
	//				"employed_until": "2021-08-09",
	//				"employer": "Chucky Pilot's Bar \u0026 Grill",
	//				"id": "did:example:7",
	//				"pilot_id": "Bravo-7",
	//				"pilot_points": 172,
	//				"role": "Customer Relationships Manager"
	//			},
	//			"id": "https://example.co.website/credentials/employee/7",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:7",
	//			"type": [
	//				"VerifiableCredential",
	//				"EmployeeCredential"
	//			]
	//		},
	//		{
	//			"@context": [
	//				"https://www.w3.org/2018/credentials/v1"
	//			],
	//			"credentialSubject": {
	//				"accrediting_institution": "Nowheresville Community College",
	//				"expiry": "2027-12-30",
	//				"id": "did:example:123",
	//				"licensed_vehicles": [
	//					"hang_glider",
	//					"kite",
	//					"Cessna 152"
	//				],
	//				"pilot_id": "4358793"
	//			},
	//			"id": "https://example.faa/credentials/123",
	//			"issuanceDate": "0001-01-01T00:00:00Z",
	//			"issuer": "did:example:123",
	//			"type": [
	//				"VerifiableCredential",
	//				"FlightCertificationCredential"
	//			]
	//		}
	//	]
	// }
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
		[]*verifiable.Presentation{receivedVP}, loader,
		WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(loader)),
	)
	if err != nil {
		panic(fmt.Errorf("presentation submission did not match definitions: %w", err))
	}

	for _, descriptor := range verifierDefinitions.InputDescriptors {
		receivedCred := matched[descriptor.ID]
		fmt.Printf(
			"verifier received the '%s' credential for the input descriptor id '%s'\n",
			receivedCred.Credential.Context[1], descriptor.ID)
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
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": uuid.New().String(),
		},
	}

	return vc
}
