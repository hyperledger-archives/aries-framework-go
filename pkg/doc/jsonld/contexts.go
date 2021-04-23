/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

// nolint:golint
import _ "embed"

// nolint:gochecknoglobals // JSON-LD context documents embedded into Go binary.
var (
	//go:embed contexts/third_party/w3.org/credentials_v1.jsonld
	w3orgCredentials []byte
	//go:embed contexts/third_party/w3.org/did_v1.jsonld
	w3orgDID []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/did_v0.11.jsonld
	w3idDIDv011 []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/did_v1.jsonld
	w3idDIDv1 []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/ldp-bbs2020_v1.jsonld
	w3idBBS []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/lds-jws2020_v1.jsonld
	w3idJWS []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/security_v1.jsonld
	w3idSecurityV1 []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/security_v2.jsonld
	w3idSecurityV2 []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/revocationList2020.jsonld
	w3idRevocationList2020 []byte
	//go:embed contexts/third_party/identity.foundation/presentation-submission_v1.jsonld
	presentationSubmission []byte
)

// nolint:gochecknoglobals // TODO: Remove as part of https://github.com/hyperledger/aries-framework-go/issues/2730
var (
	//go:embed contexts/third_party/w3.org/odrl.jsonld
	odrl []byte
	//go:embed contexts/third_party/w3.org/credentials-examples_v1.jsonld
	credentialExamples []byte
)

var embedContexts = []ContextDocument{ //nolint:gochecknoglobals
	{
		URL:         "https://www.w3.org/2018/credentials/v1",
		DocumentURL: "https://www.w3.org/2018/credentials/v1",
		Content:     w3orgCredentials,
	},
	{
		URL:         "https://www.w3.org/ns/did/v1",
		DocumentURL: "https://www.w3.org/ns/did/v1",
		Content:     w3orgDID,
	},
	{
		URL:         "https://w3id.org/did/v0.11",
		DocumentURL: "https://w3c-ccg.github.io/did-spec/contexts/did-v0.11.jsonld",
		Content:     w3idDIDv011,
	},
	{
		URL:         "https://w3id.org/did/v1",
		DocumentURL: "https://w3c-ccg.github.io/did-spec/contexts/did-v1.jsonld",
		Content:     w3idDIDv1,
	},
	{
		URL:         "https://w3id.org/security/bbs/v1",
		DocumentURL: "https://w3c-ccg.github.io/ldp-bbs2020/contexts/v1/",
		Content:     w3idBBS,
	},
	{
		URL:         "https://w3id.org/security/jws/v1",
		DocumentURL: "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
		Content:     w3idJWS,
	},
	{
		URL:         "https://w3id.org/security/v1",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v1.jsonld",
		Content:     w3idSecurityV1,
	},
	{
		URL:         "https://w3id.org/security/v2",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v2.jsonld",
		Content:     w3idSecurityV2,
	},
	{
		URL:         "https://w3id.org/vc-revocation-list-2020/v1",
		DocumentURL: "https://w3c-ccg.github.io/vc-status-rl-2020/contexts/vc-revocation-list-2020/v1.jsonld",
		Content:     w3idRevocationList2020,
	},
	{
		URL:         "https://identity.foundation/presentation-exchange/submission/v1",
		DocumentURL: "https://identity.foundation/presentation-exchange/submission/v1/",
		Content:     presentationSubmission,
	},
	// Contexts below are used when making calls from BDD tests. Remove them as soon as there is ability
	// to add these contexts thru API (#2730).
	{
		URL:         "https://www.w3.org/ns/odrl.jsonld",
		DocumentURL: "https://www.w3.org/ns/odrl.jsonld",
		Content:     odrl,
	},
	{
		URL:         "https://www.w3.org/2018/credentials/examples/v1",
		DocumentURL: "https://www.w3.org/2018/credentials/examples/v1",
		Content:     credentialExamples,
	},
}
