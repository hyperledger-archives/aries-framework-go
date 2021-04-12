/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import "embed"

// embedFS contains JSON-LD context documents from the "contexts" folder.
//go:embed contexts/*.jsonld
var embedFS embed.FS //nolint:gochecknoglobals

// DefaultContexts contains a list of context documents embedded into Go binary. They can be preloaded into
// the underlying storage using jsonld.WithContexts() option upon loader creation.
// TODO: Update with more default contexts.
var DefaultContexts = []ContextDocument{ //nolint:gochecknoglobals
	{
		URL:         "https://w3id.org/security/v1",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v1.jsonld",
		Path:        "contexts/security_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/security/v2",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v2.jsonld",
		Path:        "contexts/security_v2.jsonld",
	},
	{
		URL:         "https://w3id.org/security/jws/v1",
		DocumentURL: "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
		Path:        "contexts/lds-jws2020_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/security/bbs/v1",
		DocumentURL: "https://w3c-ccg.github.io/ldp-bbs2020/contexts/v1/",
		Path:        "contexts/bbs2020.jsonld",
	},
}
