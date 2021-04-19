/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import "embed"

// EmbedFS contains JSON-LD context documents from the "third_party" folder.
//go:embed third_party/*
var EmbedFS embed.FS //nolint:gochecknoglobals

// EmbedContexts contains a list of context documents embedded into Go binary.
var EmbedContexts = []ContextDocument{ //nolint:gochecknoglobals
	{
		URL:         "https://www.w3.org/2018/credentials/examples/v1",
		DocumentURL: "",
		Path:        "third_party/w3.org/credentials-examples_v1.jsonld",
	},
	{
		URL:         "https://www.w3.org/2018/credentials/v1",
		DocumentURL: "",
		Path:        "third_party/w3.org/credentials_v1.jsonld",
	},
	{
		URL:         "https://www.w3.org/ns/did/v1",
		DocumentURL: "",
		Path:        "third_party/w3.org/did_v1.jsonld",
	},
	{
		URL:         "https://www.w3.org/ns/odrl.jsonld",
		DocumentURL: "",
		Path:        "third_party/w3.org/odrl.jsonld",
	},
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
		Path:        "third_party/w3c-ccg.github.io/citizenship_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/did/v0.11",
		DocumentURL: "https://w3c-ccg.github.io/did-spec/contexts/did-v0.11.jsonld",
		Path:        "third_party/w3c-ccg.github.io/did_v0.11.jsonld",
	},
	{
		URL:         "https://w3id.org/did/v1",
		DocumentURL: "https://w3c-ccg.github.io/did-spec/contexts/did-v1.jsonld",
		Path:        "third_party/w3c-ccg.github.io/did_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/security/bbs/v1",
		DocumentURL: "https://w3c-ccg.github.io/ldp-bbs2020/contexts/v1/",
		Path:        "third_party/w3c-ccg.github.io/ldp-bbs2020_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/security/jws/v1",
		DocumentURL: "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
		Path:        "third_party/w3c-ccg.github.io/lds-jws2020_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/security/v1",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v1.jsonld",
		Path:        "third_party/w3c-ccg.github.io/security_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/security/v2",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v2.jsonld",
		Path:        "third_party/w3c-ccg.github.io/security_v2.jsonld",
	},
	{
		URL:         "https://identity.foundation/presentation-exchange/submission/v1",
		DocumentURL: "https://identity.foundation/presentation-exchange/submission/v1/",
		Path:        "third_party/identity.foundation/presentation-submission_v1.jsonld",
	},
	{
		URL:         "https://trustbloc.github.io/context/vc/credentials-v1.jsonld",
		DocumentURL: "",
		Path:        "third_party/trustbloc.github.io/credentials_v1.jsonld",
	},
	{
		URL:         "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
		DocumentURL: "",
		Path:        "third_party/trustbloc.github.io/examples_v1.jsonld",
	},
}
