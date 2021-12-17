/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package embed

import (
	_ "embed" //nolint:gci // required for go:embed

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
)

// nolint:gochecknoglobals // required for go:embed
var (
	//go:embed third_party/w3.org/credentials_v1.jsonld
	w3orgCredentials []byte
	//go:embed third_party/w3.org/did_v1.jsonld
	w3orgDID []byte
	//go:embed third_party/w3c-ccg.github.io/did_v0.11.jsonld
	w3idDIDv011 []byte
	//go:embed third_party/w3c-ccg.github.io/did_v1.jsonld
	w3idDIDv1 []byte
	//go:embed third_party/w3c-ccg.github.io/did_docres_v1.jsonld
	w3idDIDDocRes []byte
	//go:embed third_party/w3c-ccg.github.io/ldp-bbs2020_v1.jsonld
	ldpBBS2020 []byte
	//go:embed third_party/w3c-ccg.github.io/lds-jws2020_v1.jsonld
	ldsJWS2020 []byte
	//go:embed third_party/w3c-ccg.github.io/security_v1.jsonld
	securityV1 []byte
	//go:embed third_party/w3c-ccg.github.io/security_v2.jsonld
	securityV2 []byte
	//go:embed third_party/w3c-ccg.github.io/revocationList2020.jsonld
	revocationList2020 []byte
	//go:embed third_party/digitalbazaar.github.io/ed25519-signature-2018-v1.jsonld
	ed255192018 []byte
	//go:embed third_party/identity.foundation/presentation-submission_v1.jsonld
	presentationSubmission []byte
	//go:embed third_party/ns.did.ai/x25519-2019_v1.jsonld
	x255192019 []byte
	//go:embed third_party/ns.did.ai/secp256k1-2019_v1.jsonld
	secp256k12019 []byte
	//go:embed third_party/identity.foundation/credential-fulfillment.jsonld
	credentialFulfillment []byte
	//go:embed third_party/identity.foundation/credential-application.jsonld
	credentialApplication []byte
)

// Contexts contains JSON-LD contexts embedded into a Go binary.
var Contexts = []ldcontext.Document{ //nolint:gochecknoglobals
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
		URL:         "https://w3id.org/did-resolution/v1",
		DocumentURL: "https://w3c-ccg.github.io/did-resolution/contexts/did-resolution-v1.json",
		Content:     w3idDIDDocRes,
	},
	{
		URL:         "https://w3id.org/security/bbs/v1",
		DocumentURL: "https://w3c-ccg.github.io/ldp-bbs2020/contexts/v1/",
		Content:     ldpBBS2020,
	},
	{
		URL:         "https://w3id.org/security/suites/bls12381-2020/v1",
		DocumentURL: "https://w3c-ccg.github.io/ldp-bbs2020/contexts/v1/",
		Content:     ldpBBS2020,
	},
	{
		URL:         "https://w3id.org/security/jws/v1",
		DocumentURL: "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
		Content:     ldsJWS2020,
	},
	{
		URL:         "https://w3id.org/security/suites/jws-2020/v1",
		DocumentURL: "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
		Content:     ldsJWS2020,
	},
	{
		URL:         "https://w3id.org/security/v1",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v1.jsonld",
		Content:     securityV1,
	},
	{
		URL:         "https://w3id.org/security/v2",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v2.jsonld",
		Content:     securityV2,
	},
	{
		URL:         "https://w3id.org/vc-revocation-list-2020/v1",
		DocumentURL: "https://w3c-ccg.github.io/vc-status-rl-2020/contexts/vc-revocation-list-2020/v1.jsonld",
		Content:     revocationList2020,
	},
	{
		URL:         "https://identity.foundation/presentation-exchange/submission/v1",
		DocumentURL: "https://identity.foundation/presentation-exchange/submission/v1/",
		Content:     presentationSubmission,
	},
	{
		URL:         "https://w3id.org/security/suites/ed25519-2018/v1",
		DocumentURL: "https://digitalbazaar.github.io/ed25519-signature-2018-context/contexts/ed25519-signature-2018-v1.jsonld", //nolint:lll
		Content:     ed255192018,
	},
	{
		URL:         "https://w3id.org/security/suites/x25519-2019/v1",
		DocumentURL: "https://ns.did.ai/suites/x25519-2019/v1/",
		Content:     x255192019,
	},
	{
		URL:         "https://w3id.org/security/suites/secp256k1-2019/v1",
		DocumentURL: "https://ns.did.ai/suites/secp256k1-2019/v1/",
		Content:     secp256k12019,
	},
	{
		URL:         "https://identity.foundation/credential-manifest/fulfillment/v1",
		DocumentURL: "https://identity.foundation/credential-manifest/fulfillment/v1",
		Content:     credentialFulfillment,
	},
	{
		URL:         "https://identity.foundation/credential-manifest/application/v1",
		DocumentURL: "https://identity.foundation/credential-manifest/application/v1",
		Content:     credentialApplication,
	},
}
