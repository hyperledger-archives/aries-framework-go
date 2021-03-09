/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

func TestNewCachingDocLoader(t *testing.T) {
	u := "https://www.w3.org/2018/credentials/v1"
	loader := NewCachingDocLoader(ld.NewRFC7324CachingDocumentLoader(httpclient()))
	_, err := loader.LoadDocument(u)
	require.Error(t, err, "network should be disabled")

	loader.AddDocument(u, jsonVCWithProperContexts)

	expectedDoc := &ld.RemoteDocument{
		DocumentURL: "https://www.w3.org/2018/credentials/v1",
		Document:    jsonVCWithProperContexts,
		ContextURL:  "",
	}

	doc, err := loader.LoadDocument(u)
	require.NoError(t, err)
	require.EqualValues(t, expectedDoc, doc)
}

// nolint
const jsonVCWithProperContexts = `{
    "@context": "https://w3id.org/security/v2",
    "id": "http://www.example.org/foo/documents/a3480d17-df7f-449f-9480-e2c35e20a865",
    "allowedAction": ["read", "write"],
    "invocationTarget": {
        "ID": "http://www.example.org/foo/documents/a3480d17-df7f-449f-9480-e2c35e20a865",
        "Type": "urn:edv:document"
    },
    "proof": [{
        "created": "2020-12-04T15:28:14.673975717-05:00",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..6OfIULug35ZmoU7lysChVpD6sjYfV71UwxqIZ8u0woYSIzRtzCo3MsZJw6cGIZMEaMssnQyRqIzo8B0yHEL2Dw",
        "nonce": "da7CcJahAdFG0GXN-JnS2f2mywcFNtaLyXtGVqku2DwVwUaJbGpUQjhlNi5kDbS4ZMi2cNhEN5ac6LponS-C9w",
        "proofPurpose": "capabilityDelegation",
        "type": "Ed25519Signature2018",
        "verificationMethod": "did:key:z6MkmkFTTczYKzU94t45sG65iZi2HA21tAU9ns8bXSmBEap4#z6MkmkFTTczYKzU94t45sG65iZi2HA21tAU9ns8bXSmBEap4"
    }]
}`
