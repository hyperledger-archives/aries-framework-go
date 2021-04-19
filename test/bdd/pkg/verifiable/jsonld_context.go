/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"embed"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
)

//go:embed testdata/contexts/*.jsonld
var embedFS embed.FS //nolint:gochecknoglobals

//nolint:gochecknoglobals // embedded JSON-LD test contexts
var jsonLDContexts = []jsonld.ContextDocument{
	{
		URL:         "https://www.w3.org/2018/credentials/v1",
		DocumentURL: "",
		Path:        "testdata/contexts/credentials_v1.jsonld",
	},
	{
		URL:         "https://www.w3.org/2018/credentials/examples/v1",
		DocumentURL: "",
		Path:        "testdata/contexts/credentials-examples_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/security/bbs/v1",
		DocumentURL: "https://w3c-ccg.github.io/ldp-bbs2020/contexts/v1/",
		Path:        "testdata/contexts/ldp-bbs2020_v1.jsonld",
	},
	{
		URL:         "https://www.w3.org/ns/odrl.jsonld",
		DocumentURL: "",
		Path:        "testdata/contexts/odrl.jsonld",
	},
	{
		URL:         "https://w3id.org/security/v1",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v1.jsonld",
		Path:        "testdata/contexts/security_v1.jsonld",
	},
	{
		URL:         "https://w3id.org/security/v2",
		DocumentURL: "https://w3c-ccg.github.io/security-vocab/contexts/security-v2.jsonld",
		Path:        "testdata/contexts/security_v2.jsonld",
	},
	{
		URL:         "https://trustbloc.github.io/context/vc/credentials-v1.jsonld",
		DocumentURL: "",
		Path:        "testdata/contexts/trustbloc-credentials_v1.jsonld",
	},
	{
		URL:         "https://identity.foundation/presentation-exchange/submission/v1",
		DocumentURL: "https://identity.foundation/presentation-exchange/submission/v1/",
		Path:        "testdata/contexts/presentation-submission_v1.jsonld",
	},
}
