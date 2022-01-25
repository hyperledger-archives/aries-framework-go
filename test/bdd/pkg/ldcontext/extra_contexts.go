/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldcontext

import (
	_ "embed" //nolint:gci // required for go:embed

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
)

// nolint:gochecknoglobals // embedded test contexts
var (
	//go:embed testdata/credentials-examples_v1.jsonld
	credentialExamples []byte
	//go:embed testdata/odrl.jsonld
	odrl []byte
	//go:embed testdata/citizenship-v1.jsonld
	citizenshipV1 []byte
)

// Extra returns extra JSON-LD contexts used in tests.
func Extra() []ldcontext.Document {
	return []ldcontext.Document{
		{
			URL:     "https://www.w3.org/2018/credentials/examples/v1",
			Content: credentialExamples,
		},
		{
			URL:     "https://www.w3.org/ns/odrl.jsonld",
			Content: odrl,
		},
		{
			URL:     "https://w3id.org/citizenship/v1",
			Content: citizenshipV1,
		},
	}
}
