/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// Example of a Verifier verifying the presentation submission of a Holder.
func ExamplePresentationDefinitions_Match() {
	// verifier sends their presentation definitions to the holder
	verifierDefinitions := &PresentationDefinitions{
		InputDescriptors: []*InputDescriptor{
			{
				ID: "banking",
				Schema: &Schema{
					URI: "https://example.context.jsonld/account",
				},
			},
			{
				ID: "residence",
				Schema: &Schema{
					URI: "https://example.context.jsonld/address",
				},
			},
		},
	}

	// holder fetches their credentials
	accountCredential := newVC([]string{"https://example.context.jsonld/account"})
	addressCredential := newVC([]string{"https://example.context.jsonld/address"})

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

	// verifier parses the vp
	// note: parsing this VP without verifying the proof just for example purposes.
	//       Always verify proofs in production!
	receivedVP, err := verifiable.ParseUnverifiedPresentation(vpBytes)
	if err != nil {
		panic(err)
	}

	// verifier matches the received VP against their definitions
	matched, err := verifierDefinitions.Match(
		receivedVP,
		WithJSONLDDocumentLoader(cachedJSONLDContextLoader(map[string]string{
			"https://example.context.jsonld/account": exampleJSONLDContext,
			"https://example.context.jsonld/address": exampleJSONLDContext,
		})),
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
	vp := &verifiable.Presentation{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://identity.foundation/presentation-exchange/submission/v1",
		},
		Type: []string{
			"VerifiablePresentation",
			"PresentationSubmission",
		},
	}

	if submission != nil {
		vp.CustomFields = make(map[string]interface{})
		vp.CustomFields["presentation_submission"] = toExampleMap(submission)
	}

	if len(vcs) > 0 {
		creds := make([]interface{}, len(vcs))

		for i := range vcs {
			creds[i] = vcs[i]
		}

		err := vp.SetCredentials(creds...)
		if err != nil {
			return nil, err
		}
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

func cachedJSONLDContextLoader(ctxURLToVocab map[string]string) *ld.CachingDocumentLoader {
	loader := verifiable.CachingJSONLDLoader()

	for contextURL, vocab := range ctxURLToVocab {
		reader, err := ld.DocumentFromReader(strings.NewReader(vocab))
		if err != nil {
			panic(err)
		}

		loader.AddDocument(contextURL, reader)
	}

	return loader
}

const exampleJSONLDContext = `{
    "@context":{
      "@version":1.1,
      "@protected":true,
      "name":"http://schema.org/name",
      "ex":"https://example.org/examples#",
      "xsd":"http://www.w3.org/2001/XMLSchema#"
   }
}`
