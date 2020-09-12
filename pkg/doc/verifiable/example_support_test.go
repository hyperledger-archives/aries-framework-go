/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable_test

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

type UniversityDegree struct {
	Type       string `json:"type,omitempty"`
	University string `json:"university,omitempty"`
}

type UniversityDegreeSubject struct {
	ID     string           `json:"id,omitempty"`
	Name   string           `json:"name,omitempty"`
	Spouse string           `json:"spouse,omitempty"`
	Degree UniversityDegree `json:"degree,omitempty"`
}

type UniversityDegreeCredential struct {
	*verifiable.Credential

	ReferenceNumber int `json:"referenceNumber,omitempty"`
}

func (udc *UniversityDegreeCredential) MarshalJSON() ([]byte, error) {
	// todo too complex! (https://github.com/hyperledger/aries-framework-go/issues/847)
	c := udc.Credential
	cp := *c

	cp.CustomFields = map[string]interface{}{
		"referenceNumber": udc.ReferenceNumber,
	}

	return json.Marshal(&cp)
}

func getJSONLDDocumentLoader() *ld.CachingDocumentLoader {
	loader := verifiable.CachingJSONLDLoader()

	addJSONLDCachedContextFromFile(loader,
		"https://www.w3.org/2018/credentials/examples/v1", "vc_example.jsonld")

	addJSONLDCachedContextFromFile(loader,
		"https://trustbloc.github.io/context/vc/examples-v1.jsonld", "trustbloc_example.jsonld")

	addJSONLDCachedContextFromFile(loader,
		"https://trustbloc.github.io/context/vc/credentials-v1.jsonld", "trustbloc_jwk2020_example.jsonld")

	addJSONLDCachedContextFromFile(loader, "https://www.w3.org/ns/odrl.jsonld", "odrl.jsonld")
	addJSONLDCachedContextFromFile(loader, "https://w3id.org/security/v1", "security_v1.jsonld")
	addJSONLDCachedContextFromFile(loader, "https://w3id.org/security/v2", "security_v2.jsonld")

	return loader
}

func addJSONLDCachedContextFromFile(loader *ld.CachingDocumentLoader, contextURL, contextFile string) {
	contextContent, err := ioutil.ReadFile(filepath.Clean(filepath.Join("testdata/context", contextFile)))
	if err != nil {
		panic(err)
	}

	addJSONLDCachedContext(loader, contextURL, string(contextContent))
}

func addJSONLDCachedContext(loader *ld.CachingDocumentLoader, contextURL, contextContent string) {
	reader, err := ld.DocumentFromReader(strings.NewReader(contextContent))
	if err != nil {
		panic(err)
	}

	loader.AddDocument(contextURL, reader)
}
